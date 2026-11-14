//! Shared protocol password check (#355-0): one port of frozen Go's
//! `pwhash.CheckAppPassword` and `auth.CheckPassword` (`pwhash.CheckPassword`
//! plus the fail-closed guest refusal) for every protocol adapter: IMAP now,
//! DAV Basic (#355a), SMTP submission and LDAP later. Each caller states its
//! [`Policy`] explicitly; there is no default.
//!
//! Owner ruling (2026-11-14): IMAP and DAV refuse a TOTP user's account
//! password ([`TotpAccountPassword::Refuse`]); app passwords still work. This
//! diverges from frozen Go, which admits it. The flag is read by the per-call
//! account SELECT and checked before the cache and verification.
//!
//! Go's 60 s verification cache is kept, bounded, and keyed by a per-instance
//! HMAC over (user id, email, stored hash, presented secret). No plaintext or
//! stable password digest is held; expired tags are swept on every insert, and
//! any credential rotation misses at once. The account lookup, the enabled
//! filter, the TOTP rule and the guest refusal run on every call; a hit skips
//! only bcrypt/SM3 verification and the self-heal. App passwords never enter
//! the cache.
use ring::{hmac, rand::SystemRandom};
use setjoin_pg::{ScopedExecutor, Type};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant},
};

/// Go's `authCache` lifetime.
pub const CACHE_TTL: Duration = Duration::from_secs(60);
/// Upper bound on live entries; Go's `sync.Map` is unbounded.
pub const CACHE_CAPACITY: usize = 4096;

/// Which password kinds a protocol accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accept {
    /// `auth.CheckPassword` only.
    AccountPassword,
    /// `pwhash.CheckAppPassword` only; never falls back to the account
    /// password (DAV Basic, owner decision for #355a).
    AppPassword,
    /// Go's IMAP/SMTP order: the app password first, then the account
    /// password after the app-password failure row.
    AppPasswordThenAccountPassword,
}

/// Whether an app password held by a guest account is refused. Frozen Go's
/// `CheckAppPassword` has no guest check; IMAP keeps that parity and new
/// surfaces refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestAppPasswords {
    Admit,
    Refuse,
}

/// Whether a user with `totp_enabled` may authenticate with the account
/// password. `Refuse` is the owner ruling for IMAP and DAV (security
/// divergence); `Admit` is frozen Go's behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAccountPassword {
    Admit,
    Refuse,
}

/// The complete, explicit credential policy of one protocol adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub accept: Accept,
    pub guest_app_passwords: GuestAppPasswords,
    pub totp_account_password: TotpAccountPassword,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub user_id: i64,
    /// The stored `users.email` (Go's `User.Email`), not the presented spelling.
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    AppPassword(Verified),
    AccountPassword(Verified),
    /// One answer for every refusal: wrong or unknown secret, unknown or
    /// disabled account, TOTP account password, guest, revoked/expired app
    /// password, database error (no oracle).
    Refused,
}

/// Verify `secret` for `email` under the caller's explicit policy. Writes
/// only Go's app-password bookkeeping/audit rows and the best-effort
/// self-heal; account-password audit rows belong to the caller
/// ([`record_event`], provider `bcrypt` for IMAP, `basic` for DAV).
pub async fn verify(
    exec: &ScopedExecutor,
    cache: &PasswordCache,
    email: &str,
    secret: &str,
    policy: Policy,
) -> Verdict {
    if matches!(
        policy.accept,
        Accept::AppPassword | Accept::AppPasswordThenAccountPassword
    ) {
        if let Some(user) = app_password(exec, email, secret, policy.guest_app_passwords).await {
            return Verdict::AppPassword(user);
        }
        if policy.accept == Accept::AppPassword {
            return Verdict::Refused;
        }
    }
    match account_password(exec, cache, email, secret, policy.totp_account_password).await {
        Some(user) => Verdict::AccountPassword(user),
        None => Verdict::Refused,
    }
}

/// `pwhash.LogAuthEvent`: best effort, errors swallowed; empty email/IP are NULL.
pub async fn record_event(
    exec: &ScopedExecutor,
    user: Option<i64>,
    event: &str,
    provider: &str,
    email: &str,
    ip: Option<&str>,
) {
    let _ = exec
        .record_protocol_auth_event(
            user,
            event,
            provider,
            non_empty(email),
            ip.and_then(non_empty),
        )
        .await;
}

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// `pwhash.CheckAppPassword`: SHA-256 of the presented token, bookkeeping and
/// the audit rows on both outcomes (no IP, as Go). Never cached.
async fn app_password(
    exec: &ScopedExecutor,
    email: &str,
    token: &str,
    guests: GuestAppPasswords,
) -> Option<Verified> {
    let hash: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let found = exec
        .read(
            "SELECT u.id FROM users u JOIN app_passwords ap ON ap.user_id = u.id \
             WHERE lower(u.email) = lower($1) AND u.enabled = TRUE AND ap.token_hash = $2 \
             AND ap.revoked_at IS NULL AND (ap.expires_at IS NULL OR ap.expires_at > now())",
            &[(&email, Type::TEXT), (&hash, Type::TEXT)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()));
    let Some(user) = found else {
        record_event(exec, None, "login_failed", "app_password", email, None).await;
        return None;
    };
    if guests == GuestAppPasswords::Refuse && !not_guest(exec, user).await {
        record_event(exec, None, "login_failed", "app_password", email, None).await;
        return None;
    }
    let _ = exec.touch_app_password(user, &hash).await;
    record_event(exec, Some(user), "login", "app_password", email, None).await;
    // Go re-reads the enabled user; a vanished row fails the credential after
    // the success row was already written.
    let rows = exec
        .read(
            "SELECT id, email FROM users WHERE id = $1 AND enabled = TRUE",
            &[(&user, Type::INT8)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    Some(Verified {
        user_id: row.try_get(0).ok()?,
        email: row.try_get(1).ok()?,
    })
}

/// `auth.CheckPassword`: per-call lookup (enabled filter and TOTP flag),
/// cached bcrypt/SM3 verification, best-effort below-floor self-heal guarded
/// on the verified hash, then the fail-closed guest refusal.
async fn account_password(
    exec: &ScopedExecutor,
    cache: &PasswordCache,
    email: &str,
    password: &str,
    totp: TotpAccountPassword,
) -> Option<Verified> {
    let rows = exec
        .read(
            "SELECT u.id, u.email, u.password_hash, u.totp_enabled FROM users u \
             JOIN domains d ON d.id = u.domain_id WHERE u.email = $1 AND u.enabled = TRUE",
            &[(&email, Type::TEXT)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    let id: i64 = row.try_get(0).ok()?;
    let stored_email: String = row.try_get(1).ok()?;
    let hash: String = row.try_get(2).ok()?;
    let totp_enabled: bool = row.try_get(3).ok()?;
    if hash.is_empty() {
        return None;
    }
    // Owner ruling (#355-0 F1): checked on every call, before the cache and
    // before any hash work, so neither a warm cache nor a password oracle
    // remains for TOTP users.
    if totp_enabled && totp == TotpAccountPassword::Refuse {
        return None;
    }
    let tag = cache.tag(id, email, &hash, password);
    let cached = tag.as_ref().is_some_and(|t| cache.hit(t, Instant::now()));
    if !cached {
        let (stored, presented) = (hash.clone(), password.to_owned());
        let (valid, upgrade) = tokio::task::spawn_blocking(move || {
            let valid = crate::password::verify(&stored, &presented);
            let upgrade = valid
                .then(|| crate::password::standard_upgrade(&stored, &presented))
                .flatten();
            (valid, upgrade)
        })
        .await
        .ok()?;
        if !valid {
            return None;
        }
        if let Some(new) = upgrade {
            let _ = exec
                .upgrade_legacy_protocol_password(id, email, &hash, &new)
                .await;
        }
        if let Some(tag) = tag {
            cache.insert(tag, Instant::now());
        }
    }
    if !not_guest(exec, id).await {
        return None;
    }
    Some(Verified {
        user_id: id,
        email: stored_email,
    })
}

/// `is_guest_account` is SECURITY DEFINER; any error or missing row fails closed.
async fn not_guest(exec: &ScopedExecutor, user: i64) -> bool {
    exec.read("SELECT is_guest_account($1)", &[(&user, Type::INT8)])
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        == Some(false)
}

/// Bounded verification cache. Entries are expiry instants keyed by an
/// HMAC tag; the key is random per instance and never leaves it. Without a
/// key (RNG failure) nothing is cached. A tag is a fast verifier for its
/// password only while both it and the in-memory key exist; expired tags are
/// swept on every insert and removed on lookup.
pub struct PasswordCache {
    key: Option<hmac::Key>,
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<[u8; 32], Instant>>,
    hits: AtomicUsize,
}

impl Default for PasswordCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordCache {
    pub fn new() -> Self {
        Self::with_limits(CACHE_TTL, CACHE_CAPACITY)
    }

    pub fn with_limits(ttl: Duration, capacity: usize) -> Self {
        Self {
            key: hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new()).ok(),
            ttl,
            capacity,
            entries: Mutex::new(HashMap::new()),
            hits: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Lookups answered from the cache (test observation; never a security input).
    #[doc(hidden)]
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], Instant>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn tag(&self, user: i64, email: &str, hash: &str, password: &str) -> Option<[u8; 32]> {
        let key = self.key.as_ref()?;
        let mut context = hmac::Context::with_key(key);
        context.update(&user.to_be_bytes());
        for part in [email, hash, password] {
            context.update(&(part.len() as u64).to_be_bytes());
            context.update(part.as_bytes());
        }
        let mut out = [0; 32];
        out.copy_from_slice(context.sign().as_ref());
        Some(out)
    }

    fn hit(&self, tag: &[u8; 32], now: Instant) -> bool {
        let mut entries = self.lock();
        match entries.get(tag) {
            Some(expires) if now < *expires => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                true
            }
            Some(_) => {
                entries.remove(tag);
                false
            }
            None => false,
        }
    }

    fn insert(&self, tag: [u8; 32], now: Instant) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut entries = self.lock();
        // F6: sweep on every insert (inserts follow a full bcrypt/SM3 verify,
        // so the O(capacity) pass is negligible).
        entries.retain(|_, expires| now < *expires);
        if entries.len() >= self.capacity && !entries.contains_key(&tag) {
            return;
        }
        entries.insert(tag, now + self.ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_within_ttl_and_miss_after() {
        let cache = PasswordCache::with_limits(Duration::from_secs(60), 8);
        let now = Instant::now();
        let tag = cache.tag(1, "a@x.test", "$2a$10$h", "pw").unwrap();
        assert!(!cache.hit(&tag, now));
        cache.insert(tag, now);
        assert!(cache.hit(&tag, now + Duration::from_secs(59)));
        assert!(!cache.hit(&tag, now + Duration::from_secs(60)));
        assert!(cache.is_empty(), "an expired entry is removed on lookup");
    }

    #[test]
    fn expired_tags_are_swept_on_every_insert() {
        let cache = PasswordCache::with_limits(Duration::from_secs(60), 8);
        let now = Instant::now();
        let t = |n: i64| cache.tag(n, "a@x.test", "hash", "pw").unwrap();
        cache.insert(t(1), now);
        cache.insert(t(2), now + Duration::from_secs(30));
        assert_eq!(cache.len(), 2);
        cache.insert(t(3), now + Duration::from_secs(61));
        assert_eq!(cache.len(), 2, "t(1) is swept although the map is not full");
        assert!(!cache.hit(&t(1), now + Duration::from_secs(61)));
    }

    #[test]
    fn tag_binds_user_email_stored_hash_and_secret() {
        let cache = PasswordCache::new();
        let base = cache.tag(1, "a@x.test", "hash", "pw").unwrap();
        assert_eq!(cache.tag(1, "a@x.test", "hash", "pw").unwrap(), base);
        for other in [
            cache.tag(2, "a@x.test", "hash", "pw"),
            cache.tag(1, "b@x.test", "hash", "pw"),
            cache.tag(1, "a@x.test", "hash2", "pw"),
            cache.tag(1, "a@x.test", "hash", "pw2"),
            cache.tag(1, "a@x.testh", "ash", "pw"),
        ] {
            assert_ne!(other.unwrap(), base);
        }
    }

    #[test]
    fn tags_are_keyed_per_cache_and_are_not_a_password_digest() {
        let (a, b) = (PasswordCache::new(), PasswordCache::new());
        let tag = a.tag(1, "a@x.test", "hash", "pw").unwrap();
        assert_ne!(Some(tag), b.tag(1, "a@x.test", "hash", "pw"));
        let digest: [u8; 32] = Sha256::digest(b"pw").into();
        assert_ne!(tag, digest);
    }

    #[test]
    fn capacity_is_bounded_and_expired_entries_make_room() {
        let cache = PasswordCache::with_limits(Duration::from_secs(60), 2);
        let now = Instant::now();
        let t = |n: i64| cache.tag(n, "a@x.test", "hash", "pw").unwrap();
        cache.insert(t(1), now);
        cache.insert(t(2), now);
        cache.insert(t(3), now);
        assert_eq!(cache.len(), 2);
        assert!(!cache.hit(&t(3), now));
        let later = now + Duration::from_secs(61);
        cache.insert(t(3), later);
        assert_eq!(cache.len(), 1);
        assert!(cache.hit(&t(3), later));
    }

    #[test]
    fn zero_capacity_or_zero_ttl_never_caches() {
        let now = Instant::now();
        for cache in [
            PasswordCache::with_limits(Duration::from_secs(60), 0),
            PasswordCache::with_limits(Duration::ZERO, 8),
        ] {
            let tag = cache.tag(1, "a@x.test", "hash", "pw").unwrap();
            cache.insert(tag, now);
            assert!(cache.is_empty());
            assert!(!cache.hit(&tag, now));
        }
    }
}
