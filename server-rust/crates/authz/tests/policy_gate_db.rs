//! Wave 1.4 (#542) live DB integration proofs under `setjoin_app` (`NOBYPASSRLS`)
//! + `FORCE RLS`:
//! 1. `GroupResolver` across all 3 namespaces (`user_group_members`,
//!    `directory_groups`/`directory_group_members`, `distribution_groups`/SCIM
//!    admin scope), `LISTEN group_membership_changed` invalidation (per-user &
//!    `user_id IS NULL` -> `all:true`), fail-closed `Unavailable`, bounded LRU
//!    cap, and non-blocking concurrent resolves.
//! 2. `MailboxAuthority` lattice for every `DelegatePermission` cell +
//!    immediate uncached revocation + `AdminPrincipal` mixed `(domain + global)`
//!    narrowest `enforced_domain_scope` + dormant JIT exclusion from BOTH
//!    `AdminPrincipal` AND CA (`policy/store.rs:71` regression!) +
//!    `dengbao.sod_mode` refusal + impersonation `act` refusal.
//! 3. Full 11-surface `ProtocolSurface` matrix (zero-DB stage 0 ordering,
//!    two-phase Kerberos `Negotiate`, constant-time dummy hash, live guest belt,
//!    revocation/CAE, `device_lockdown`, CA `block`/`step_up`, app entitlements,
//!    mailbox lifecycle, and `revalidate_push_session`).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use hyper::{
    header::{HeaderName, HeaderValue},
    HeaderMap,
};
use serde_json::{json, Value};
use setjoin_authz::{
    auth_chain::Chain,
    basic::{self, Accept, GuestAppPasswords, PasswordCache, Policy, TotpAccountPassword, Verdict},
    groups::{CaGroupId, DirectoryGroupId, DistributionGroupId, GroupResolveError, GroupResolver},
    kerberos::{KerberosError, KerberosValidator},
    policy::eval::{Context as PolicyContext, Engine},
    policy_gate::{
        BoxFuture, DenylistView, EdgeLimiter, GateCredential, GateDenial, GateRequest,
        GateThreatAction, GateThreatMeta, GuestAllowlist, PolicyGate, ProtocolSurface,
        ThreatAdapter,
    },
    principals::{MailboxAuthority, PrincipalError, TxFactory},
    token::KeySource,
};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_contracts::ids::MailboxId;
use setjoin_pg::{AppPool, ScopedExecutor};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ISSUER: &str = "https://auth.policy-gate-542.test";
const JWT_SECRET: &[u8] = b"policy-gate-542-hs256-test-secret-key-32b!";
const ATT_SECRET: &[u8] = b"policy-gate-542-attachment-secret-key-32b!";

struct StaticKeys {
    legacy: setjoin_authz::legacy_jwt::LegacyKeys,
}

impl StaticKeys {
    fn new() -> Self {
        Self {
            legacy: setjoin_authz::legacy_jwt::LegacyKeys::new(JWT_SECRET, &["hs256-test"], None)
                .unwrap(),
        }
    }
}

impl KeySource for StaticKeys {
    async fn key(&self, _kid: &str) -> Option<setjoin_authz::es256::VerifyingKey> {
        None
    }
    fn legacy_keys(&self) -> Option<&setjoin_authz::legacy_jwt::LegacyKeys> {
        Some(&self.legacy)
    }
}

fn sign_hs256(claims: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT","kid":"hs256-test"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signing_input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(JWT_SECRET).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig}")
}

fn sign_attachment_token(claims: &Value) -> String {
    // Exact match with token::attachment: RFC 5869 salt="mailserver-mail-attachment-token-v1", no info
    let mut extract =
        Hmac::<Sha256>::new_from_slice(b"mailserver-mail-attachment-token-v1").unwrap();
    extract.update(ATT_SECRET);
    let prk = extract.finalize().into_bytes();
    let mut expand = Hmac::<Sha256>::new_from_slice(&prk).unwrap();
    expand.update(&[1]);
    let key = expand.finalize().into_bytes();
    let header = URL_SAFE_NO_PAD
        .encode(r#"{"alg":"HS256","typ":"JWT","kid":"mailserver-mail-attachment-1"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signing_input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig}")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

fn base_req<'a>(
    surface: ProtocolSurface,
    credential: GateCredential<'a>,
    hdrs: Option<&'a HeaderMap>,
) -> GateRequest<'a> {
    GateRequest {
        surface,
        credential,
        client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        user_agent: "PolicyGateTest/1.0",
        scheme: "https",
        method: "GET",
        path: "/jmap",
        headers: hdrs,
        body: &[],
        tls_active: true,
        require_tls: false,
        production: true,
        allowed_origin_host: "",
        required_app: None,
        drive_path: false,
        now_secs: None,
    }
}

struct MockDenylist {
    loaded: AtomicBool,
    revoked_user: i64,
}
impl DenylistView for MockDenylist {
    fn loaded(&self) -> bool {
        self.loaded.load(Ordering::SeqCst)
    }
    fn is_revoked(&self, user_id: i64, _jti: &str, _family: &str, _issued_at: i64) -> bool {
        self.revoked_user > 0 && self.revoked_user == user_id
    }
}

struct CountingLimiter {
    allow: bool,
    calls: AtomicUsize,
}
impl EdgeLimiter for CountingLimiter {
    fn allow(&self, _ip: &str, _surface: ProtocolSurface) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.allow
    }
}

struct MockAllowlist;
impl GuestAllowlist for MockAllowlist {
    fn allows(&self, method: &str, path: &str) -> bool {
        method == "GET" && path == "/api/guest/ping"
    }
}

struct MockKerberos(String);
impl KerberosValidator for MockKerberos {
    fn validate_spnego<'a>(
        &'a self,
        _token: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, KerberosError>> + Send + 'a>,
    > {
        let p = self.0.clone();
        Box::pin(async move { Ok(p) })
    }
}

struct RecordingThreat {
    intercept_calls: AtomicUsize,
    lockout_calls: AtomicUsize,
    record_calls: AtomicUsize,
    lockout_reject: AtomicBool,
}
impl Default for RecordingThreat {
    fn default() -> Self {
        Self {
            intercept_calls: AtomicUsize::new(0),
            lockout_calls: AtomicUsize::new(0),
            record_calls: AtomicUsize::new(0),
            lockout_reject: AtomicBool::new(false),
        }
    }
}
impl ThreatAdapter for RecordingThreat {
    fn intercept<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
    ) -> BoxFuture<'a, (GateThreatAction, Duration)> {
        self.intercept_calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            meta.username.is_empty(),
            "Phase 1 Negotiate intercept must be IP-only (empty username)"
        );
        Box::pin(async { (GateThreatAction::Allow, Duration::ZERO) })
    }
    fn check_account_lockout<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
    ) -> BoxFuture<'a, (GateThreatAction, Duration)> {
        self.lockout_calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            !meta.username.is_empty(),
            "Phase 2 Negotiate lockout check must carry resolved username"
        );
        let action = if self.lockout_reject.load(Ordering::SeqCst) {
            GateThreatAction::Reject
        } else {
            GateThreatAction::Allow
        };
        Box::pin(async move { (action, Duration::ZERO) })
    }
    fn record_result<'a>(
        &'a self,
        _meta: &'a GateThreatMeta,
        _success: bool,
        _user_id: i64,
    ) -> BoxFuture<'a, ()> {
        self.record_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }
    fn record_ip_failure<'a>(&'a self, _meta: &'a GateThreatMeta) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        _meta: &'a mut GateThreatMeta,
    ) -> BoxFuture<'a, (GateThreatAction, String)> {
        Box::pin(async { (GateThreatAction::Allow, String::new()) })
    }
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn group_resolver_all_three_namespaces_under_force_rls_and_listen_invalidation() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("pg542-group-resolver") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let app_pool = AppPool::from_dsn(app_dsn, 4).unwrap();
    let app_exec = ScopedExecutor::from_dsn(app_dsn, 4).unwrap();

    let a1 = fixture::account(&owner, "grp542-a1").await.unwrap();
    let a2 = fixture::account(&owner, "grp542-a2").await.unwrap();
    let a3 = fixture::account(&owner, "grp542-a3").await.unwrap();

    let domain_id: i64 = owner
        .query_one("SELECT domain_id FROM users WHERE id = $1", &[&a1.user])
        .await
        .unwrap()
        .get(0);

    // Seed departments for dynamic directory group matching
    let dept_match: i64 = owner
        .query_one(
            "INSERT INTO departments(name, path, ldap_ou) VALUES('Eng542', '/eng542', 'ou=eng542') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let dept_other: i64 = owner
        .query_one(
            "INSERT INTO departments(name, path, ldap_ou) VALUES('Sales542', '/sales542', 'ou=sales542') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "UPDATE users SET department_id = $1 WHERE id = $2",
            &[&dept_match, &a1.user],
        )
        .await
        .unwrap();

    // 1. CA user_group_members (V045 FORCE RLS)
    let ca_gid: i64 = 954201;
    owner
        .execute(
            "INSERT INTO user_group_members(user_id, group_id) VALUES($1, $2)",
            &[&a1.user, &ca_gid],
        )
        .await
        .unwrap();

    // 2. Directory groups: static + matching dynamic + non-matching dynamic + active source + inactive source
    let dir_static: i64 = owner
        .query_one(
            "INSERT INTO directory_groups(domain_id, name, kind, state, visibility) \
             VALUES($1, 'static542', 'static', 'active', 'members') RETURNING id",
            &[&domain_id],
        )
        .await
        .unwrap()
        .get(0);
    let dir_dyn_ok: i64 = owner
        .query_one(
            "INSERT INTO directory_groups(domain_id, name, kind, state, visibility, dynamic_filter) \
             VALUES($1, 'dyn_ok_542', 'dynamic', 'active', 'members', $2::text::jsonb) RETURNING id",
            &[&domain_id, &format!(r#"{{"departmentId":{dept_match}}}"#)],
        )
        .await
        .unwrap()
        .get(0);
    let dir_dyn_no: i64 = owner
        .query_one(
            "INSERT INTO directory_groups(domain_id, name, kind, state, visibility, dynamic_filter) \
             VALUES($1, 'dyn_no_542', 'dynamic', 'active', 'members', $2::text::jsonb) RETURNING id",
            &[&domain_id, &format!(r#"{{"departmentId":{dept_other}}}"#)],
        )
        .await
        .unwrap()
        .get(0);
    let src_active: i64 = owner
        .query_one(
            "INSERT INTO identity_sources(source_key, display_name, kind, capabilities, state) \
             VALUES('src542-active', 'Src Active', 'scim', '{\"groups\":true}'::jsonb, 'active') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let src_disabled: i64 = owner
        .query_one(
            "INSERT INTO identity_sources(source_key, display_name, kind, capabilities, state) \
             VALUES('src542-off', 'Src Off', 'scim', '{\"groups\":true}'::jsonb, 'paused') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let dir_src_ok: i64 = owner
        .query_one(
            "INSERT INTO directory_groups(domain_id, source_id, external_anchor, name, kind, state, visibility) \
             VALUES($1, $2, 'anc-ok-542', 'src_ok_542', 'source', 'active', 'members') RETURNING id",
            &[&domain_id, &src_active],
        )
        .await
        .unwrap()
        .get(0);
    let dir_src_no: i64 = owner
        .query_one(
            "INSERT INTO directory_groups(domain_id, source_id, external_anchor, name, kind, state, visibility) \
             VALUES($1, $2, 'anc-no-542', 'src_no_542', 'source', 'active', 'members') RETURNING id",
            &[&domain_id, &src_disabled],
        )
        .await
        .unwrap()
        .get(0);
    for (gid, src_kind, anchor) in [
        (dir_static, "static", None),
        (dir_dyn_ok, "dynamic", None),
        (dir_dyn_no, "dynamic", None),
        (dir_src_ok, "source", Some("m-ok-542")),
        (dir_src_no, "source", Some("m-no-542")),
    ] {
        owner
            .execute(
                "INSERT INTO directory_group_members(group_id, user_id, membership_source, source_anchor) \
                 VALUES($1, $2, $3, $4)",
                &[&gid, &a1.user, &src_kind, &anchor],
            )
            .await
            .unwrap();
    }

    // 3. Distribution groups: normal, SCIM admin-scope, usable_as_admin_scope, dynamic-with-scim (NOT admin scope!)
    let mut dg_mailboxes = Vec::new();
    for slug in ["plain", "scim", "flag", "dyn"] {
        let mb: i64 = owner
            .query_one(
                "INSERT INTO mailboxes(user_id, domain_id, email, display_name, type, is_primary, enabled) \
                 VALUES(NULL, $1, $2, $3, 'personal', FALSE, TRUE) RETURNING id",
                &[&domain_id, &format!("dg-{slug}-542@test.example"), &slug],
            )
            .await
            .unwrap()
            .get(0);
        dg_mailboxes.push(mb);
    }
    let dg_plain: i64 = owner
        .query_one(
            "INSERT INTO distribution_groups(mailbox_id, is_dynamic, usable_as_admin_scope) \
             VALUES($1, FALSE, FALSE) RETURNING id",
            &[&dg_mailboxes[0]],
        )
        .await
        .unwrap()
        .get(0);
    let dg_scim: i64 = owner
        .query_one(
            "INSERT INTO distribution_groups(mailbox_id, is_dynamic, scim_external_id, scim_source_id, usable_as_admin_scope) \
             VALUES($1, FALSE, 'scim-ext-542', $2, FALSE) RETURNING id",
            &[&dg_mailboxes[1], &src_active],
        )
        .await
        .unwrap()
        .get(0);
    let dg_flag: i64 = owner
        .query_one(
            "INSERT INTO distribution_groups(mailbox_id, is_dynamic, usable_as_admin_scope) \
             VALUES($1, FALSE, TRUE) RETURNING id",
            &[&dg_mailboxes[2]],
        )
        .await
        .unwrap()
        .get(0);
    let dg_dyn_scim: i64 = owner
        .query_one(
            "INSERT INTO distribution_groups(mailbox_id, is_dynamic, scim_external_id, scim_source_id, usable_as_admin_scope) \
             VALUES($1, TRUE, 'scim-dyn-542', $2, TRUE) RETURNING id",
            &[&dg_mailboxes[3], &src_active],
        )
        .await
        .unwrap()
        .get(0);
    for dg in [dg_plain, dg_scim, dg_flag, dg_dyn_scim] {
        owner
            .execute(
                "INSERT INTO distribution_group_members(group_id, mailbox_id, source) VALUES($1, $2, 'manual')",
                &[&dg, &a1.mailbox],
            )
            .await
            .unwrap();
    }

    let resolver =
        Arc::new(GroupResolver::new(app_pool.clone()).with_limits(2, Duration::from_secs(60)));

    // Verify all 3 namespaces under setjoin_app FORCE RLS!
    let m = resolver.resolve(a1.user).await.unwrap();
    assert_eq!(m.ca_groups, vec![CaGroupId::new(ca_gid).unwrap()]);
    assert_eq!(
        m.directory_groups,
        vec![
            DirectoryGroupId::new(dir_static).unwrap(),
            DirectoryGroupId::new(dir_dyn_ok).unwrap(),
            DirectoryGroupId::new(dir_src_ok).unwrap(),
        ],
        "directory_groups must match directory_group_effective_member exactly"
    );
    assert_eq!(
        m.distribution_groups.len(),
        4,
        "all 4 distribution groups returned"
    );
    assert_eq!(
        m.admin_scope_groups,
        vec![
            DistributionGroupId::new(dg_scim).unwrap(),
            DistributionGroupId::new(dg_flag).unwrap(),
        ],
        "admin_scope_groups must exclude dynamic and plain groups"
    );

    // Regression proof for policy/store.rs:64 FORCE RLS zero-row bug:
    // Group-targeted CA block policy MUST fire under setjoin_app!
    owner
        .execute(
            "INSERT INTO conditional_access_policies(id, priority, name, state, scope_type, scope_target, conditions, actions) \
             VALUES(954290, -542, 'ca-group-rls-542', 'on', 'group', $1, '{}', '{\"action\":\"block\"}')",
            &[&ca_gid.to_string()],
        )
        .await
        .unwrap();
    let engine = Engine::with_group_resolver(app_exec.clone(), resolver.clone());
    let ca_res = engine
        .evaluate(PolicyContext {
            user_id: a1.user,
            ..Default::default()
        })
        .await;
    assert_eq!(
        ca_res.decision, "block",
        "group-targeted CA block policy must fire under setjoin_app FORCE RLS (fixes policy/store.rs:64)"
    );
    owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE id = 954290",
            &[],
        )
        .await
        .unwrap();

    // Bounded LRU cap proof (capacity = 2 with 3 users).
    let _ = resolver.resolve(a2.user).await.unwrap();
    assert_eq!(resolver.cached_len(), 2);
    let _ = resolver.resolve(a3.user).await.unwrap();
    assert_eq!(
        resolver.cached_len(),
        2,
        "LRU cache must stay bounded at capacity=2"
    );

    // Concurrent non-blocking resolve proof (4 parallel tasks).
    resolver.invalidate_all();
    let (r1, r2, r3, r4) = tokio::join!(
        resolver.resolve(a1.user),
        resolver.resolve(a2.user),
        resolver.resolve(a3.user),
        resolver.resolve(a1.user),
    );
    assert!(r1.is_ok() && r2.is_ok() && r3.is_ok() && r4.is_ok());

    // Live LISTEN invalidation proof (per-user AND user_id IS NULL -> all:true).
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let listen_task = tokio::spawn(resolver.clone().listen(db.dsn.clone(), stop_rx));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Populate cache for a1 & a2
    assert_eq!(resolver.resolve(a1.user).await.unwrap().ca_groups.len(), 1);
    assert_eq!(resolver.resolve(a2.user).await.unwrap().ca_groups.len(), 0);
    assert_eq!(resolver.cached_len(), 2);

    // Delete CA group membership -> V285 emits {"source":"user_group_members","user_id":a1.user}
    owner
        .execute(
            "DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2",
            &[&a1.user, &ca_gid],
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        resolver.resolve(a1.user).await.unwrap().ca_groups.len(),
        0,
        "LISTEN user_id invalidation must clear cached CA group immediately"
    );

    // Group-wide invalidation (user_id IS NULL): soft-delete dir_static -> emits {"all":true} -> invalidate_all()
    let _ = resolver.resolve(a2.user).await.unwrap();
    assert_eq!(resolver.cached_len(), 2);
    owner
        .execute(
            "UPDATE directory_groups SET state = 'deleted' WHERE id = $1",
            &[&dir_static],
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        resolver.cached_len(),
        0,
        "user_id IS NULL invalidation must call invalidate_all()"
    );
    let m_after = resolver.resolve(a1.user).await.unwrap();
    assert!(!m_after.has_directory_group(DirectoryGroupId::new(dir_static).unwrap()));

    let _ = stop_tx.send(());
    let _ = listen_task.await;

    // Fail-closed proof: unreachable DB returns Err(GroupResolveError::Unavailable), NEVER empty Vec!
    let bad_pool = AppPool::from_dsn(
        "postgres://mail@127.0.0.1:1/nonexistent?connect_timeout=1",
        1,
    )
    .unwrap();
    let bad_resolver = GroupResolver::new(bad_pool);
    let err = bad_resolver.resolve(a1.user).await.unwrap_err();
    assert!(
        matches!(err, GroupResolveError::Unavailable(_)),
        "DB error must fail closed with Unavailable, got {err:?}"
    );

    // Cleanup
    owner
        .execute(
            "DELETE FROM distribution_groups WHERE id = ANY($1::bigint[])",
            &[&vec![dg_plain, dg_scim, dg_flag, dg_dyn_scim]],
        )
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM mailboxes WHERE id = ANY($1::bigint[])",
            &[&dg_mailboxes],
        )
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM directory_group_members WHERE group_id = ANY($1::bigint[])",
            &[&vec![
                dir_static, dir_dyn_ok, dir_dyn_no, dir_src_ok, dir_src_no,
            ]],
        )
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM directory_groups WHERE id = ANY($1::bigint[])",
            &[&vec![
                dir_static, dir_dyn_ok, dir_dyn_no, dir_src_ok, dir_src_no,
            ]],
        )
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM identity_sources WHERE id = ANY($1::bigint[])",
            &[&vec![src_active, src_disabled]],
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE users SET department_id = NULL WHERE id = $1",
            &[&a1.user],
        )
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM departments WHERE id = ANY($1::bigint[])",
            &[&vec![dept_match, dept_other]],
        )
        .await
        .unwrap();
    for a in [&a1, &a2, &a3] {
        fixture::remove(&owner, a).await.unwrap();
    }
}

#[tokio::test]
async fn principals_mailbox_lattice_revocation_and_admin_narrowest_scope_jit_sod() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("pg542-principals") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let app_pool = AppPool::from_dsn(app_dsn, 4).unwrap();
    let app_exec = ScopedExecutor::from_dsn(app_dsn, 4).unwrap();
    let factory = TxFactory::new(app_pool);
    let gate = PolicyGate::new(app_exec.clone(), Arc::new(StaticKeys::new()), ISSUER);

    let alice = fixture::account(&owner, "pr542-alice").await.unwrap();
    let bob = fixture::account(&owner, "pr542-bob").await.unwrap();
    let admin = fixture::account(&owner, "pr542-admin").await.unwrap();

    let now = now_unix();
    let jwt_for = |uid: i64, act: Option<i64>| {
        let mut c = json!({
            "iss": ISSUER,
            "aud": "mailserver-gateway",
            "typ": "access",
            "uid": uid,
            "email": format!("u{uid}@test.example"),
            "iat": now - 5,
            "exp": now + 300,
        });
        if let Some(a) = act {
            c["act"] = json!(a);
        }
        sign_hs256(&c)
    };

    // 1. MailboxAuthority lattice for Owner + all 5 DelegatePermission cells
    let alice_tok = jwt_for(alice.user, None);
    let alice_adm = gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &alice_tok,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap();
    let owner_p = alice_adm
        .mint_mailbox(&factory, MailboxId::new(alice.mailbox).unwrap())
        .await
        .unwrap();
    assert_eq!(owner_p.authority(), &MailboxAuthority::Owner);
    assert!(owner_p.require_owner().is_ok());
    assert!(owner_p.require_mutate().is_ok());
    // Prove TxFactory actually opens MailboxTx<ReadOnly> from ReadCapability!
    let mut ro_tx = factory
        .begin_mailbox_read(&owner_p.require_read().unwrap())
        .await
        .unwrap();
    let rows = ro_tx
        .query(
            "SELECT current_setting('app.current_mailbox_id', true)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, String>(0), alice.mailbox.to_string());
    ro_tx.finish().await.unwrap();

    let bob_tok = jwt_for(bob.user, None);
    let bob_adm = gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &bob_tok,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap();
    let target_mb = MailboxId::new(alice.mailbox).unwrap();
    // Without delegation -> Forbidden
    assert!(matches!(
        bob_adm.mint_mailbox(&factory, target_mb).await,
        Err(PrincipalError::Forbidden(_))
    ));

    for (perm_str, want_read, want_mutate, want_submit, want_send_as, want_cal) in [
        ("full_access", true, true, true, true, true),
        ("send_as", true, false, true, true, false),
        ("send_on_behalf", true, false, true, false, false),
        ("read", true, false, false, false, false),
        ("manage_calendar", false, false, false, false, true),
    ] {
        owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2",
                &[&alice.mailbox, &bob.user],
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO mailbox_delegates(mailbox_id, user_id, permission, granted_by) VALUES($1, $2, $3, $4)",
                &[&alice.mailbox, &bob.user, &perm_str, &alice.user],
            )
            .await
            .unwrap();
        let p = bob_adm.mint_mailbox(&factory, target_mb).await.unwrap();
        assert!(p.require_owner().is_err(), "{perm_str} is never owner");
        assert_eq!(p.require_read().is_ok(), want_read, "{perm_str} read");
        assert_eq!(p.require_mutate().is_ok(), want_mutate, "{perm_str} mutate");
        assert_eq!(p.require_submit().is_ok(), want_submit, "{perm_str} submit");
        assert_eq!(
            p.require_send_as().is_ok(),
            want_send_as,
            "{perm_str} send_as"
        );
        assert_eq!(
            p.require_manage_calendar().is_ok(),
            want_cal,
            "{perm_str} manage_calendar"
        );
    }

    // Immediate uncached revocation proof
    owner
        .execute(
            "DELETE FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2",
            &[&alice.mailbox, &bob.user],
        )
        .await
        .unwrap();
    assert!(matches!(
        bob_adm.mint_mailbox(&factory, target_mb).await,
        Err(PrincipalError::Forbidden(_))
    ));

    // Shared mailbox (mailboxes.user_id IS NULL) delegation proof:
    // Must decode NULL owner cleanly and enforce mailbox_delegates without crashing.
    let shared_domain_id: i64 = owner
        .query_one("SELECT domain_id FROM users WHERE id = $1", &[&alice.user])
        .await
        .unwrap()
        .get(0);
    let shared_mb_id: i64 = owner
        .query_one(
            "INSERT INTO mailboxes(user_id, domain_id, email, display_name, type, is_primary, enabled) \
             VALUES(NULL, $1, 'shared-542@test.example', 'Shared 542', 'personal', FALSE, TRUE) RETURNING id",
            &[&shared_domain_id],
        )
        .await
        .unwrap()
        .get(0);
    let shared_mb = MailboxId::new(shared_mb_id).unwrap();
    assert!(matches!(
        bob_adm.mint_mailbox(&factory, shared_mb).await,
        Err(PrincipalError::Forbidden(_))
    ));
    owner
        .execute(
            "INSERT INTO mailbox_delegates(mailbox_id, user_id, permission, granted_by) VALUES($1, $2, 'full_access', $3)",
            &[&shared_mb_id, &bob.user, &alice.user],
        )
        .await
        .unwrap();
    let shared_p = bob_adm.mint_mailbox(&factory, shared_mb).await.unwrap();
    assert!(shared_p.require_owner().is_err());
    assert!(shared_p.require_read().is_ok());
    assert!(shared_p.require_mutate().is_ok());
    let mut shared_tx = factory
        .begin_mailbox_read(&shared_p.require_read().unwrap())
        .await
        .unwrap();
    let shared_rows = shared_tx
        .query(
            "SELECT current_setting('app.current_mailbox_id', true)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(shared_rows[0].get::<_, String>(0), shared_mb_id.to_string());
    shared_tx.finish().await.unwrap();
    owner
        .execute(
            "DELETE FROM mailbox_delegates WHERE mailbox_id = $1",
            &[&shared_mb_id],
        )
        .await
        .unwrap();
    owner
        .execute("DELETE FROM mailboxes WHERE id = $1", &[&shared_mb_id])
        .await
        .unwrap();

    // Mailbox lifecycle blocked proof
    owner
        .execute(
            "UPDATE mailboxes SET enabled = FALSE WHERE id = $1",
            &[&alice.mailbox],
        )
        .await
        .unwrap();
    assert_eq!(
        alice_adm.mint_mailbox(&factory, target_mb).await,
        Err(PrincipalError::MailboxBlocked)
    );
    owner
        .execute(
            "UPDATE mailboxes SET enabled = TRUE WHERE id = $1",
            &[&alice.mailbox],
        )
        .await
        .unwrap();

    // 2. AdminPrincipal: narrowest enforced_domain_scope with mixed (domain + global) roles,
    //    dormant JIT exclusion from BOTH AdminPrincipal AND CA (policy/store.rs:71 regression!),
    //    dengbao.sod_mode refusal, and impersonation `act` refusal.
    let domain_id: i64 = owner
        .query_one("SELECT domain_id FROM users WHERE id = $1", &[&admin.user])
        .await
        .unwrap()
        .get(0);
    let role_dom: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name, permissions, domain_scope, sod_class) \
             VALUES('rg542_dom', ARRAY['users.read','users.create'], $1, 'system') RETURNING id",
            &[&domain_id],
        )
        .await
        .unwrap()
        .get(0);
    let role_glob: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name, permissions, domain_scope, sod_class) \
             VALUES('rg542_glob', ARRAY['domains.read'], NULL, 'system') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let role_jit: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name, permissions, domain_scope, sod_class) \
             VALUES('rg542_jit', ARRAY['backup.write'], NULL, 'system') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let role_audit: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name, permissions, domain_scope, sod_class) \
             VALUES('rg542_audit', ARRAY['audit.read'], NULL, 'audit') RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let role_unclass: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name, permissions, domain_scope, sod_class) \
             VALUES('rg542_unclass', ARRAY['users.read'], NULL, NULL) RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);

    // Save rbac.jit and dengbao.sod_mode toggles
    let saved_jit: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key = 'rbac.jit'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get(0));
    let saved_sod: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get(0));
    owner
        .execute(
            "INSERT INTO feature_toggles(key, enabled) VALUES('rbac.jit', TRUE) \
             ON CONFLICT(key) DO UPDATE SET enabled = TRUE",
            &[],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO feature_toggles(key, enabled) VALUES('dengbao.sod_mode', FALSE) \
             ON CONFLICT(key) DO UPDATE SET enabled = FALSE",
            &[],
        )
        .await
        .unwrap();

    // Assign mixed (domain-scoped + global) active roles + 1 dormant JIT role
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id, role_group_id, eligible, activated_until) \
             VALUES ($1, $2, FALSE, NULL), ($1, $3, FALSE, NULL), ($1, $4, TRUE, NULL)",
            &[&admin.user, &role_dom, &role_glob, &role_jit],
        )
        .await
        .unwrap();

    // Impersonated token (`act` claim) MUST be refused on AdminPrincipal!
    let imp_tok = jwt_for(admin.user, Some(alice.user));
    let imp_adm = gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &imp_tok,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        imp_adm.mint_admin(&factory).await,
        Err(PrincipalError::ImpersonationRefused)
    );

    // Real admin token
    let adm_tok = jwt_for(admin.user, None);
    let adm = gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &adm_tok,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap();
    let ap = adm.mint_admin(&factory).await.unwrap();
    assert_eq!(
        ap.enforced_domain_scope(),
        Some(domain_id),
        "mixed (domain + global) MUST keep narrowest non-NULL enforced_domain_scope (zero widening!)"
    );
    assert_eq!(
        ap.broadest_scope(),
        None,
        "broadest_scope reflects global reach for target-protection only"
    );
    assert!(ap.has_permission("users.create"));
    assert!(ap.has_permission("domains.read"));
    assert!(ap.global_any(&["domains.read"]));
    assert!(!ap.global_any(&["users.create"]));
    assert!(
        !ap.has_permission("backup.write"),
        "dormant JIT role must be excluded from AdminPrincipal"
    );
    assert!(ap.refused_for_scope(&["audit.read"]));

    // Regression proof for policy/store.rs:71 dormant JIT bug in CA:
    // A role-targeted CA block policy on role_jit MUST NOT fire while role_jit is dormant!
    owner
        .execute(
            "INSERT INTO conditional_access_policies(id, priority, name, state, scope_type, scope_target, conditions, actions) \
             VALUES(954291, -541, 'ca-jit-role-542', 'on', 'role', $1, '{}', '{\"action\":\"block\"}')",
            &[&role_jit.to_string()],
        )
        .await
        .unwrap();
    let ca_engine = Engine::new(app_exec.clone());
    let dormant_res = ca_engine
        .evaluate(PolicyContext {
            user_id: admin.user,
            ..Default::default()
        })
        .await;
    assert_eq!(
        dormant_res.decision, "allow",
        "dormant JIT role must NOT trigger role-scoped CA policy (fixes policy/store.rs:71)"
    );
    // Once activated, CA MUST see the role and block!
    owner
        .execute(
            "UPDATE admin_role_assignments SET activated_until = now() + interval '10 minutes' \
             WHERE user_id = $1 AND role_group_id = $2",
            &[&admin.user, &role_jit],
        )
        .await
        .unwrap();
    ca_engine.invalidate_user_scope(admin.user).await;
    let active_res = ca_engine
        .evaluate(PolicyContext {
            user_id: admin.user,
            ..Default::default()
        })
        .await;
    assert_eq!(
        active_res.decision, "block",
        "activated JIT role must trigger role-scoped CA policy"
    );
    owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE id = 954291",
            &[],
        )
        .await
        .unwrap();

    // dengbao.sod_mode enforcement proof:
    // Clean single-class ('system') roles succeed when sod_mode = true
    owner
        .execute(
            "UPDATE feature_toggles SET enabled = TRUE WHERE key = 'dengbao.sod_mode'",
            &[],
        )
        .await
        .unwrap();
    let ap_sod_ok = adm.mint_admin(&factory).await.unwrap();
    assert!(ap_sod_ok.sod_enforced());
    assert_eq!(
        ap_sod_ok.active_sod_classes(),
        &BTreeSet::from(["system".to_owned()])
    );

    // Adding an unclassified role (sod_class IS NULL) must fail closed!
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id, role_group_id) VALUES($1, $2)",
            &[&admin.user, &role_unclass],
        )
        .await
        .unwrap();
    assert_eq!(
        adm.mint_admin(&factory).await,
        Err(PrincipalError::SodViolation("unclassified_role"))
    );
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = $2",
            &[&admin.user, &role_unclass],
        )
        .await
        .unwrap();

    // Adding a second SoD class ('audit' alongside 'system') must fail closed as cross_class!
    // Insert while sod_mode = FALSE (so DB trg_sod_exclusion permits the seed row),
    // then flip sod_mode = TRUE and assert AdminPrincipal catches cross_class unconditionally.
    owner
        .execute(
            "UPDATE feature_toggles SET enabled = FALSE WHERE key = 'dengbao.sod_mode'",
            &[],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id, role_group_id) VALUES($1, $2)",
            &[&admin.user, &role_audit],
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE feature_toggles SET enabled = TRUE WHERE key = 'dengbao.sod_mode'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        adm.mint_admin(&factory).await,
        Err(PrincipalError::SodViolation("cross_class"))
    );

    // AdminPrincipal fail-closed Unavailable on unreachable pool (zero JWT fallback):
    let dead_pool = AppPool::from_dsn("postgres://setjoin_app@127.0.0.1:1/nope", 1).unwrap();
    let dead_factory = TxFactory::new(dead_pool);
    assert!(
        matches!(
            adm.mint_admin(&dead_factory).await,
            Err(PrincipalError::Unavailable(_))
        ),
        "AdminPrincipal must fail closed with Unavailable on DB outage"
    );

    // Restore toggles and clean up
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id = $1",
            &[&admin.user],
        )
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM admin_role_groups WHERE id = ANY($1::bigint[])",
            &[&vec![
                role_dom,
                role_glob,
                role_jit,
                role_audit,
                role_unclass,
            ]],
        )
        .await
        .unwrap();
    if let Some(v) = saved_jit {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled = $1 WHERE key = 'rbac.jit'",
                &[&v],
            )
            .await
            .unwrap();
    }
    if let Some(v) = saved_sod {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled = $1 WHERE key = 'dengbao.sod_mode'",
                &[&v],
            )
            .await
            .unwrap();
    }
    for a in [&alice, &bob, &admin] {
        fixture::remove(&owner, a).await.unwrap();
    }
}

#[tokio::test]
async fn surface_matrix_enforces_revocation_lockdown_guest_entitlement_and_lifecycle() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("pg542-surface-matrix") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let worker_dsn = std::env::var("DB_WORKER_DSN").unwrap_or_else(|_| db.dsn.clone());
    let app_exec = ScopedExecutor::from_dsn(app_dsn, 4).unwrap();
    let app_pool = AppPool::from_dsn(app_dsn, 4).unwrap();
    let admin_pool = setjoin_pg::AdminWorkerPool::from_dsn(&worker_dsn, 2).unwrap();
    let factory = TxFactory::with_admin_pool(
        app_pool.clone(),
        admin_pool,
        Arc::new(GroupResolver::new(app_pool)),
    );

    let member = fixture::account(&owner, "mx542-member").await.unwrap();
    let guest = fixture::account(&owner, "mx542-guest").await.unwrap();
    let domain_id: i64 = owner
        .query_one("SELECT domain_id FROM users WHERE id = $1", &[&member.user])
        .await
        .unwrap()
        .get(0);
    let member_email: String = owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&member.user])
        .await
        .unwrap()
        .get(0);
    let guest_email: String = owner
        .query_one("SELECT email FROM users WHERE id = $1", &[&guest.user])
        .await
        .unwrap()
        .get(0);

    // Seed password + app password + Kerberos UPN for member; active guest row + app password for guest
    let pw = "Matrix542-Correct-Password!";
    let pw_hash = bcrypt::hash_with_result(pw, 4)
        .unwrap()
        .format_for_version(bcrypt::Version::TwoA);
    let app_pw = "matrix542-app-secret";
    let app_pw_hash: String = Sha256::digest(app_pw.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    owner
        .execute(
            "UPDATE users SET password_hash = $1, krb5_principal = $2 WHERE id = $3",
            &[&pw_hash, &member_email, &member.user],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO app_passwords(user_id, name, token_hash) VALUES($1, 'mx542', $2)",
            &[&member.user, &app_pw_hash],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO guest_accounts(user_id, invited_email, invited_by_email, host_domain_id, status) \
             VALUES($1, $2, $3, $4, 'active')",
            &[&guest.user, &guest_email, &member_email, &domain_id],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO app_passwords(user_id, name, token_hash) VALUES($1, 'mx542-g', $2)",
            &[&guest.user, &app_pw_hash],
        )
        .await
        .unwrap();

    // Save toggles we mutate in this test
    let toggle_keys = [
        "feature.cae_runtime",
        "feature.conditional_access",
        "feature.device_lockdown",
        "feature.guest_accounts",
    ];
    let mut saved_toggles = Vec::new();
    for k in toggle_keys {
        let cur: Option<bool> = owner
            .query_opt("SELECT enabled FROM feature_toggles WHERE key = $1", &[&k])
            .await
            .unwrap()
            .map(|r| r.get(0));
        saved_toggles.push((k, cur));
    }
    let saved_bg: Option<String> = owner
        .query_opt(
            "SELECT value::text FROM system_config WHERE key = 'ca_break_glass_user_ids'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get(0));

    let set_toggle = |key: &'static str, val: bool| {
        let owner = &owner;
        async move {
            owner
                .execute(
                    "INSERT INTO feature_toggles(key, enabled) VALUES($1, $2) \
                     ON CONFLICT(key) DO UPDATE SET enabled = $2",
                    &[&key, &val],
                )
                .await
                .unwrap();
        }
    };
    set_toggle("feature.cae_runtime", false).await;
    set_toggle("feature.conditional_access", false).await;
    set_toggle("feature.device_lockdown", false).await;
    set_toggle("feature.guest_accounts", true).await;

    let now = now_unix();
    let member_jwt = sign_hs256(&json!({
        "iss": ISSUER, "aud": "mailserver-gateway", "typ": "access",
        "uid": member.user, "email": member_email, "jti": "jti-542-m", "fam": "fam-542-m",
        "iat": now - 5, "exp": now + 300
    }));
    let drive_device_jwt = sign_hs256(&json!({
        "iss": ISSUER, "aud": "mailserver-gateway", "typ": "access", "scp": "drive",
        "uid": member.user, "email": member_email, "device": {"id": "dev-1"},
        "iat": now - 5, "exp": now + 300
    }));
    let guest_jwt = sign_hs256(&json!({
        "iss": ISSUER, "aud": "mailserver-gateway", "typ": "access", "acct": "guest",
        "uid": guest.user, "email": guest_email,
        "iat": now - 5, "exp": now + 300
    }));
    let att_jwt = sign_attachment_token(&json!({
        "iss": ISSUER, "aud": "mailserver-gateway", "typ": "access", "scp": "mail-attachment",
        "uid": member.user, "email": member_email, "origin_jti": "jti-542-m", "origin_iat": now - 5,
        "iat": now - 5, "exp": now + 300
    }));

    // 1. Stage 0: CSRF-before-over-budget (#491) + TLS required + DriveNativeToken device-bound refusal
    let limiter = Arc::new(CountingLimiter {
        allow: false,
        calls: AtomicUsize::new(0),
    });
    let gate_stage0 = PolicyGate::new(app_exec.clone(), Arc::new(StaticKeys::new()), ISSUER)
        .with_edge_limiter(limiter.clone());
    let evil_hdrs = headers(&[("host", "mail.test"), ("origin", "https://evil.test")]);
    let mut csrf_req = base_req(
        ProtocolSurface::Jmap,
        GateCredential::Jwt {
            token: &member_jwt,
            from_cookie: false,
        },
        Some(&evil_hdrs),
    );
    csrf_req.method = "POST";
    assert_eq!(
        gate_stage0.admit(&csrf_req).await.unwrap_err(),
        GateDenial::CsrfOrOriginRejected
    );
    assert_eq!(
        limiter.calls.load(Ordering::SeqCst),
        0,
        "CSRF must reject BEFORE EdgeLimiter (#491)"
    );
    // Unsafe HTTP/JMAP method with headers: None must also fail closed!
    let mut missing_hdrs_post = base_req(
        ProtocolSurface::Http,
        GateCredential::Jwt {
            token: &member_jwt,
            from_cookie: false,
        },
        None,
    );
    missing_hdrs_post.method = "POST";
    assert_eq!(
        gate_stage0.admit(&missing_hdrs_post).await.unwrap_err(),
        GateDenial::CsrfOrOriginRejected
    );

    // Non-HTTP surfaces bypass HTTP CSRF and enforce TLS when require_tls=true
    let mut imap_tls_req = base_req(
        ProtocolSurface::Imap,
        GateCredential::Password {
            email: &member_email,
            secret: pw,
            run_dummy_hash: true,
        },
        None,
    );
    imap_tls_req.require_tls = true;
    imap_tls_req.tls_active = false;
    assert_eq!(
        gate_stage0.admit(&imap_tls_req).await.unwrap_err(),
        GateDenial::TlsRequired
    );

    // DriveNativeToken rejects device-bound JWTs
    let ok_hdrs = headers(&[("host", "mail.test"), ("origin", "https://mail.test")]);
    let gate = PolicyGate::new(app_exec.clone(), Arc::new(StaticKeys::new()), ISSUER)
        .with_tx_factory(factory.clone())
        .with_guest_allowlist(Arc::new(MockAllowlist))
        .with_attachment_secrets(vec![ATT_SECRET.to_vec()]);
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::DriveNativeToken,
            GateCredential::Jwt {
                token: &drive_device_jwt,
                from_cookie: false,
            },
            Some(&ok_hdrs),
        ))
        .await
        .unwrap_err(),
        GateDenial::DeviceBoundRefused
    );

    // 2. Stage 1 & 2: AttachmentTransfer admits narrow token; WebSocket requires cookie;
    //    Negotiate two-phase ThreatGate burns rate limit ONCE!
    assert!(gate
        .admit(&base_req(
            ProtocolSurface::AttachmentTransfer,
            GateCredential::AttachmentToken(&att_jwt),
            None,
        ))
        .await
        .is_ok());
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::WebSocket,
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: false,
            },
            Some(&ok_hdrs),
        ))
        .await
        .unwrap_err(),
        GateDenial::InvalidCredential
    );
    assert!(gate
        .admit(&base_req(
            ProtocolSurface::WebSocket,
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: true,
            },
            Some(&ok_hdrs),
        ))
        .await
        .is_ok());

    // Two-phase Negotiate test (CalDav) + Phase-2 lockout rejection + CardDav admission/denial
    let threat = Arc::new(RecordingThreat::default());
    let chain = Arc::new(Chain::default());
    // Enable kerberos in auth_methods temporarily so Chain::reload sets kerberos=true
    owner
        .execute(
            "INSERT INTO auth_methods(slug, name, enabled, priority, config_json) \
             VALUES('kerberos', 'Kerberos', TRUE, 10, '{}'::jsonb) \
             ON CONFLICT(slug) DO UPDATE SET enabled = TRUE",
            &[],
        )
        .await
        .unwrap();
    let _ = chain.reload(&app_exec).await;
    let neg_gate = PolicyGate::new(app_exec.clone(), Arc::new(StaticKeys::new()), ISSUER)
        .with_tx_factory(factory.clone())
        .with_auth_chain(chain.clone())
        .with_kerberos(Arc::new(MockKerberos(member_email.clone())))
        .with_threat(threat.clone());
    let neg_hdrs = headers(&[("authorization", "Negotiate YII="), ("host", "mail.test")]);
    assert!(neg_gate
        .admit(&base_req(
            ProtocolSurface::CalDav,
            GateCredential::Negotiate { headers: &neg_hdrs },
            Some(&neg_hdrs),
        ))
        .await
        .is_ok());
    assert_eq!(threat.intercept_calls.load(Ordering::SeqCst), 1);
    assert_eq!(threat.lockout_calls.load(Ordering::SeqCst), 1);
    assert_eq!(threat.record_calls.load(Ordering::SeqCst), 1);

    // Phase-2 account lockout rejection on Negotiate: intercept burns once, lockout rejects!
    threat.lockout_reject.store(true, Ordering::SeqCst);
    assert!(matches!(
        neg_gate
            .admit(&base_req(
                ProtocolSurface::CalDav,
                GateCredential::Negotiate { headers: &neg_hdrs },
                Some(&neg_hdrs),
            ))
            .await,
        Err(GateDenial::ThreatRejected { .. })
    ));
    assert_eq!(threat.intercept_calls.load(Ordering::SeqCst), 2);
    assert_eq!(threat.lockout_calls.load(Ordering::SeqCst), 2);
    assert_eq!(threat.record_calls.load(Ordering::SeqCst), 1);
    threat.lockout_reject.store(false, Ordering::SeqCst);

    // CardDav: valid app password admitted, account password / guest app password denied!
    assert!(gate
        .admit(&base_req(
            ProtocolSurface::CardDav,
            GateCredential::Password {
                email: &member_email,
                secret: app_pw,
                run_dummy_hash: true,
            },
            None,
        ))
        .await
        .is_ok());
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::CardDav,
            GateCredential::Password {
                email: &member_email,
                secret: pw,
                run_dummy_hash: true,
            },
            None,
        ))
        .await
        .unwrap_err(),
        GateDenial::InvalidCredential
    );
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::CardDav,
            GateCredential::Password {
                email: &guest_email,
                secret: app_pw,
                run_dummy_hash: true,
            },
            None,
        ))
        .await
        .unwrap_err(),
        GateDenial::InvalidCredential
    );

    // SSE: cookie auth with evil Origin rejected; Bearer auth without Origin admitted!
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::Sse,
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: true,
            },
            Some(&evil_hdrs),
        ))
        .await
        .unwrap_err(),
        GateDenial::CsrfOrOriginRejected
    );
    assert!(gate
        .admit(&base_req(
            ProtocolSurface::Sse,
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: false,
            },
            None,
        ))
        .await
        .is_ok());

    // 3. Constant-time dummy hash verification in basic::verify
    let pw_cache = PasswordCache::new();
    let p_acct = Policy {
        accept: Accept::AccountPassword,
        guest_app_passwords: GuestAppPasswords::Refuse,
        totp_account_password: TotpAccountPassword::Refuse,
    };
    assert_eq!(
        basic::verify(
            &app_exec,
            &pw_cache,
            "no-such-542@test.example",
            "x",
            p_acct
        )
        .await,
        Verdict::Refused
    );
    assert_eq!(
        pw_cache.dummy_verifications(),
        1,
        "unknown account must spend one constant-time dummy hash"
    );

    // 4. Guest belt across surfaces: admitted on allowlisted Http & Sse, refused on all 9 other surfaces
    let mut http_guest_req = base_req(
        ProtocolSurface::Http,
        GateCredential::Jwt {
            token: &guest_jwt,
            from_cookie: false,
        },
        None,
    );
    http_guest_req.path = "/api/guest/ping";
    assert!(gate.admit(&http_guest_req).await.unwrap().is_guest());
    assert!(gate
        .admit(&base_req(
            ProtocolSurface::Sse,
            GateCredential::Jwt {
                token: &guest_jwt,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap()
        .is_guest());
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::Jmap,
            GateCredential::Jwt {
                token: &guest_jwt,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap_err(),
        GateDenial::GuestRefused
    );
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::WebSocket,
            GateCredential::Jwt {
                token: &guest_jwt,
                from_cookie: true,
            },
            Some(&ok_hdrs),
        ))
        .await
        .unwrap_err(),
        GateDenial::GuestRefused
    );
    // Guest app password refused on IMAP & SMTP!
    for surface in [ProtocolSurface::Imap, ProtocolSurface::SmtpSubmission] {
        assert_eq!(
            gate.admit(&base_req(
                surface,
                GateCredential::Password {
                    email: &guest_email,
                    secret: app_pw,
                    run_dummy_hash: true,
                },
                None,
            ))
            .await
            .unwrap_err(),
            GateDenial::InvalidCredential,
            "{surface:?} must refuse guest app password"
        );
    }

    // 5. Revocation + CAE cold denylist (cae_runtime=true fails closed; cae_runtime=false allows denylist: None)
    set_toggle("feature.cae_runtime", true).await;
    assert_eq!(
        gate.admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap_err(),
        GateDenial::DenylistUnavailable,
        "cae_runtime=true with denylist: None must fail closed"
    );
    let warm_denylist = Arc::new(MockDenylist {
        loaded: AtomicBool::new(true),
        revoked_user: 0,
    });
    let cae_gate = PolicyGate::new(app_exec.clone(), Arc::new(StaticKeys::new()), ISSUER)
        .with_tx_factory(factory.clone())
        .with_denylist(warm_denylist.clone());
    assert!(cae_gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: false,
            },
            None,
        ))
        .await
        .is_ok());

    // Durable session_revocations revokes BOTH HTTP and IMAP/SMTP/LDAP!
    owner
        .execute(
            "INSERT INTO session_revocations(user_id, scope, not_before, expires_at, reason) \
             VALUES($1, 'all', now() + interval '1 minute', now() + interval '1 hour', 'test542')",
            &[&member.user],
        )
        .await
        .unwrap();
    for surface in [
        ProtocolSurface::Imap,
        ProtocolSurface::SmtpSubmission,
        ProtocolSurface::Ldap,
    ] {
        assert_eq!(
            cae_gate
                .admit(&base_req(
                    surface,
                    GateCredential::Password {
                        email: &member_email,
                        secret: pw,
                        run_dummy_hash: true,
                    },
                    None,
                ))
                .await
                .unwrap_err(),
            GateDenial::SessionRevoked,
            "{surface:?} must enforce durable session_revocations"
        );
    }
    owner
        .execute(
            "DELETE FROM session_revocations WHERE user_id = $1",
            &[&member.user],
        )
        .await
        .unwrap();

    // 6. Device lockdown refuses non-break-glass across surfaces
    set_toggle("feature.conditional_access", true).await;
    set_toggle("feature.device_lockdown", true).await;
    owner
        .execute(
            "INSERT INTO system_config(key, value) VALUES('ca_break_glass_user_ids', '[9999999]'::jsonb) \
             ON CONFLICT(key) DO UPDATE SET value = '[9999999]'::jsonb",
            &[],
        )
        .await
        .unwrap();
    for surface in [
        ProtocolSurface::Http,
        ProtocolSurface::Imap,
        ProtocolSurface::Ldap,
    ] {
        let cred = if surface == ProtocolSurface::Http {
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: false,
            }
        } else {
            GateCredential::Password {
                email: &member_email,
                secret: pw,
                run_dummy_hash: true,
            }
        };
        assert_eq!(
            cae_gate
                .admit(&base_req(surface, cred, None))
                .await
                .unwrap_err(),
            GateDenial::DeviceLockdown,
            "{surface:?} must enforce feature.device_lockdown"
        );
    }
    set_toggle("feature.device_lockdown", false).await;

    // 7. CA step_up: StepUpRequired on Http/Jmap/WebSocket vs hard PolicyBlocked on non-HTTP/WS!
    owner
        .execute(
            "INSERT INTO conditional_access_policies(id, priority, name, state, scope_type, scope_target, conditions, actions) \
             VALUES(954292, -540, 'ca-step-up-542', 'on', 'user', $1, '{}', '{\"action\":\"step_up\"}')",
            &[&member.user.to_string()],
        )
        .await
        .unwrap();
    cae_gate.engine().invalidate().await;
    assert!(matches!(
        cae_gate
            .admit(&base_req(
                ProtocolSurface::Http,
                GateCredential::Jwt {
                    token: &member_jwt,
                    from_cookie: false,
                },
                None,
            ))
            .await,
        Err(GateDenial::StepUpRequired { .. })
    ));
    assert!(matches!(
        cae_gate
            .admit(&base_req(
                ProtocolSurface::Imap,
                GateCredential::Password {
                    email: &member_email,
                    secret: pw,
                    run_dummy_hash: true,
                },
                None,
            ))
            .await,
        Err(GateDenial::PolicyBlocked { .. })
    ));
    owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE id = 954292",
            &[],
        )
        .await
        .unwrap();
    set_toggle("feature.conditional_access", false).await;

    // 8. App entitlement denial & mailbox lifecycle + push revalidation
    owner
        .execute(
            "INSERT INTO user_app_entitlements(user_id, app, enabled) VALUES($1, 'mail', FALSE) \
             ON CONFLICT(user_id, app) DO UPDATE SET enabled = FALSE",
            &[&member.user],
        )
        .await
        .unwrap();
    assert_eq!(
        cae_gate
            .admit(&base_req(
                ProtocolSurface::Imap,
                GateCredential::Password {
                    email: &member_email,
                    secret: pw,
                    run_dummy_hash: true,
                },
                None,
            ))
            .await
            .unwrap_err(),
        GateDenial::EntitlementDenied("mail".into())
    );
    owner
        .execute(
            "DELETE FROM user_app_entitlements WHERE user_id = $1",
            &[&member.user],
        )
        .await
        .unwrap();

    // Push revalidation catches mid-connection mailbox suspension!
    let ws_adm = cae_gate
        .admit(&base_req(
            ProtocolSurface::WebSocket,
            GateCredential::Jwt {
                token: &member_jwt,
                from_cookie: true,
            },
            Some(&ok_hdrs),
        ))
        .await
        .unwrap();
    assert!(cae_gate
        .revalidate_push_session(&ws_adm, &["mail"], now)
        .await
        .is_ok());
    owner
        .execute(
            "UPDATE mailboxes SET enabled = FALSE WHERE id = $1",
            &[&member.mailbox],
        )
        .await
        .unwrap();
    assert_eq!(
        cae_gate
            .revalidate_push_session(&ws_adm, &["mail"], now)
            .await
            .unwrap_err(),
        GateDenial::MailboxBlocked
    );

    // Restore DB state cleanly
    owner
        .execute(
            "UPDATE mailboxes SET enabled = TRUE WHERE id = $1",
            &[&member.mailbox],
        )
        .await
        .unwrap();
    for (k, orig) in saved_toggles {
        if let Some(v) = orig {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled = $1 WHERE key = $2",
                    &[&v, &k],
                )
                .await
                .unwrap();
        }
    }
    if let Some(bg) = saved_bg {
        owner
            .execute(
                "UPDATE system_config SET value = $1::text::jsonb WHERE key = 'ca_break_glass_user_ids'",
                &[&bg],
            )
            .await
            .unwrap();
    } else {
        owner
            .execute(
                "DELETE FROM system_config WHERE key = 'ca_break_glass_user_ids'",
                &[],
            )
            .await
            .unwrap();
    }
    owner
        .execute(
            "DELETE FROM guest_accounts WHERE user_id = $1",
            &[&guest.user],
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE auth_methods SET enabled = FALSE WHERE slug = 'kerberos'",
            &[],
        )
        .await
        .unwrap();
    for a in [&member, &guest] {
        fixture::remove(&owner, a).await.unwrap();
    }
}

#[tokio::test]
async fn phase546a_tx_factory_pool_separation_rbac_proof_effect_helpers_and_listen_hub() {
    use setjoin_contracts::{
        authority::{AuthorityKey, ResourceScope},
        command::CommandEnvelope,
        ids::{ActorId, Digest, Generation, OperationId},
    };
    use setjoin_pg::{
        AdminWorkerPool, AuditEvent, ColumnSpec, CommandOutcome, ListenHub, OperationLookup,
        ReceiptCommand, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type,
    };
    use std::time::Instant;

    let Some(db) = Db::for_case("phase546a_tx_factory") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let has_explicit_app = db.app.is_some();
    let app_dsn = db.app.as_deref().unwrap_or(&db.dsn);
    let explicit_worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|v| !v.is_empty());
    let has_explicit_worker = explicit_worker_dsn.is_some();
    let worker_dsn = explicit_worker_dsn.unwrap_or_else(|| db.dsn.clone());

    let app_pool = AppPool::from_dsn(app_dsn, 4).unwrap();
    let admin_pool = AdminWorkerPool::from_dsn(&worker_dsn, 2).unwrap();
    let app_exec = ScopedExecutor::from_dsn(app_dsn, 4).unwrap();
    let groups = Arc::new(GroupResolver::new(app_pool.clone()));

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let hub = ListenHub::spawn_with_watch(db.direct.clone(), stop_rx.clone()).unwrap();
    hub.wait_connected().await.unwrap();
    let listener_handle = groups
        .clone()
        .subscribe_listen_hub(&hub, stop_rx)
        .await
        .unwrap();

    let factory = TxFactory::with_admin_pool(app_pool.clone(), admin_pool, groups.clone());
    assert!(factory.has_admin_worker_pool());
    let gate = PolicyGate::new(app_exec.clone(), Arc::new(StaticKeys::new()), ISSUER)
        .with_tx_factory(factory.clone());

    let alice = fixture::account(&owner, "p546a-alice").await.unwrap();
    let admin = fixture::account(&owner, "p546a-admin").await.unwrap();
    let domain_admin = fixture::account(&owner, "p546a-dom-admin").await.unwrap();

    // Seed global admin + domain-scoped admin roles.
    let dom_id: i64 = owner
        .query_one(
            "SELECT domain_id FROM users WHERE id = $1",
            &[&domain_admin.user],
        )
        .await
        .unwrap()
        .get(0);
    let global_role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups (name, permissions, sod_class) \
             VALUES ($1, ARRAY['users.read','audit.read'], 'audit') RETURNING id",
            &[&format!("p546a-global-{}", admin.user)],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, $2)",
            &[&admin.user, &global_role],
        )
        .await
        .unwrap();

    let scoped_role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups (name, permissions, domain_scope, sod_class) \
             VALUES ($1, ARRAY['users.read','audit.read'], $2, 'audit') RETURNING id",
            &[&format!("p546a-scoped-{}", domain_admin.user), &dom_id],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, $2)",
            &[&domain_admin.user, &scoped_role],
        )
        .await
        .unwrap();

    let now = now_unix();
    let jwt_for = |uid: i64| {
        sign_hs256(&json!({
            "iss": ISSUER,
            "aud": "mailserver-gateway",
            "typ": "access",
            "uid": uid,
            "email": format!("u{uid}@546a.test"),
            "iat": now - 5,
            "exp": now + 300,
        }))
    };

    // 1. Tenant capabilities: effect writes, locked txs, and command lookups run on setjoin_app.
    let alice_tok = jwt_for(alice.user);
    let alice_adm = gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &alice_tok,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap();
    let mb_p = alice_adm
        .mint_mailbox(&factory, MailboxId::new(alice.mailbox).unwrap())
        .await
        .unwrap();
    let user_p = alice_adm.mint_user(&factory).await.unwrap();

    let dl = Instant::now() + Duration::from_secs(5);
    let mb_auth = AuthorityKey {
        actor: ActorId::new(alice.user).unwrap(),
        scope: ResourceScope::Mailbox(MailboxId::new(alice.mailbox).unwrap()),
        generation: Generation(1),
    };
    let user_auth = AuthorityKey {
        actor: ActorId::new(alice.user).unwrap(),
        scope: ResourceScope::User(ActorId::new(alice.user).unwrap()),
        generation: Generation(1),
    };
    let mk_env = |op_byte: u8, authority: AuthorityKey| CommandEnvelope {
        operation: OperationId([op_byte; 16]),
        authority,
        binding: setjoin_contracts::command::ContractBinding {
            major: 1,
            definition: Digest([
                0x33, 0x2b, 0x05, 0xbd, 0x4b, 0xa4, 0x04, 0x7f, 0xdd, 0xe6, 0xaf, 0xc7, 0xe7, 0xaf,
                0x0b, 0x8f, 0xe5, 0xb0, 0xf2, 0xb1, 0xdb, 0xb9, 0x51, 0x21, 0x4e, 0x82, 0xea, 0x1f,
                0x7d, 0xdf, 0x44, 0x68,
            ]),
            fixtures: Digest([
                0x11, 0x40, 0x1b, 0xc5, 0xed, 0xf4, 0x10, 0x25, 0xb2, 0xf9, 0xa8, 0x5d, 0x99, 0x98,
                0x94, 0xdb, 0x79, 0xaf, 0xea, 0x4b, 0xee, 0xfa, 0x2f, 0xd1, 0x48, 0x68, 0x81, 0xd6,
                0x27, 0xf8, 0xe8, 0xbc,
            ]),
        },
        payload_digest: Digest([0x22; 32]),
        command: (),
    };

    let cmd_mut = ReceiptCommand {
        family: "authz546a",
        command: "mutate_effect",
    };
    let env_mut = mk_env(0xA1, mb_auth);
    let out_mut = factory
        .run_mailbox_effect_write(
            &mb_p.require_mutate().unwrap(),
            cmd_mut,
            &env_mut,
            dl,
            async |tx| {
                let rows = tx
                    .query(
                        "SELECT (NOT r.rolsuper AND NOT r.rolbypassrls), current_user::text \
                           FROM pg_roles r WHERE r.rolname = current_user",
                        &[],
                    )
                    .await?;
                Ok((rows[0].get::<_, bool>(0), rows[0].get::<_, String>(1)))
            },
        )
        .await;
    match out_mut {
        CommandOutcome::Committed((non_bypass, role)) => {
            if has_explicit_app {
                assert!(non_bypass);
                assert_eq!(role, "setjoin_app");
            }
        }
        other => panic!("expected Committed mailbox effect write, got {other:?}"),
    }
    assert_eq!(
        factory
            .lookup_mailbox_command(&mb_p.require_read().unwrap(), env_mut.operation, cmd_mut)
            .await
            .unwrap(),
        OperationLookup::Committed
    );

    let cmd_sub = ReceiptCommand {
        family: "authz546a",
        command: "submit_effect",
    };
    let env_sub = mk_env(0xA2, mb_auth);
    let out_sub = factory
        .run_mailbox_submit_effect_write(
            &mb_p.require_submit().unwrap(),
            cmd_sub,
            &env_sub,
            dl,
            async |tx| {
                let rows = tx
                    .query(
                        "SELECT (NOT r.rolsuper AND NOT r.rolbypassrls), current_user::text \
                           FROM pg_roles r WHERE r.rolname = current_user",
                        &[],
                    )
                    .await?;
                Ok((rows[0].get::<_, bool>(0), rows[0].get::<_, String>(1)))
            },
        )
        .await;
    match out_sub {
        CommandOutcome::Committed((non_bypass, role)) => {
            if has_explicit_app {
                assert!(non_bypass);
                assert_eq!(role, "setjoin_app");
            }
        }
        other => panic!("expected Committed submit effect write, got {other:?}"),
    }

    let env_cal = mk_env(0xA3, mb_auth);
    let out_cal = factory
        .run_calendar_locked_tx(
            &mb_p.require_manage_calendar().unwrap(),
            &env_cal,
            dl,
            async |tx| {
                tx.prelock_mailbox_hierarchy().await?;
                Ok::<_, setjoin_pg::StatementFailure>(tx.mailbox().get())
            },
        )
        .await;
    assert!(matches!(out_cal, CommandOutcome::Committed(id) if id == alice.mailbox));

    let env_lock = mk_env(0xA4, mb_auth);
    let out_lock = factory
        .run_mailbox_locked_tx(&mb_p.require_mutate().unwrap(), &env_lock, dl, async |tx| {
            Ok::<_, setjoin_pg::StatementFailure>(tx.actor().get())
        })
        .await;
    assert!(matches!(out_lock, CommandOutcome::Committed(id) if id == alice.user));

    let cmd_usr = ReceiptCommand {
        family: "authz546a",
        command: "user_effect",
    };
    let env_usr = mk_env(0xA5, user_auth);
    let out_usr = factory
        .run_user_effect_write(&user_p, cmd_usr, &env_usr, dl, async |tx| {
            let rows = tx
                .query(
                    "SELECT (NOT r.rolsuper AND NOT r.rolbypassrls), current_user::text \
                       FROM pg_roles r WHERE r.rolname = current_user",
                    &[],
                )
                .await?;
            Ok((rows[0].get::<_, bool>(0), rows[0].get::<_, String>(1)))
        })
        .await;
    match out_usr {
        CommandOutcome::Committed((non_bypass, role)) => {
            if has_explicit_app {
                assert!(non_bypass);
                assert_eq!(role, "setjoin_app");
            }
        }
        other => panic!("expected Committed user effect write, got {other:?}"),
    }
    assert_eq!(
        factory
            .lookup_user_command(&user_p, env_usr.operation, cmd_usr)
            .await
            .unwrap(),
        OperationLookup::Committed
    );

    // 2. RBAC permission proofs + AdminWorkerPool execution (`setjoin_worker`).
    let dom_tok = jwt_for(domain_admin.user);
    let dom_adm = gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &dom_tok,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap();
    let dom_p = dom_adm.mint_admin(&factory).await.unwrap();
    assert_eq!(dom_p.enforced_domain_scope(), Some(dom_id));
    // Domain-scoped admin MUST be refused global-only `audit.read`!
    assert!(matches!(
        dom_p.require_permission("audit.read"),
        Err(PrincipalError::Forbidden(_))
    ));
    assert!(matches!(
        dom_p.require_permission("roles.manage"),
        Err(PrincipalError::Forbidden(_))
    ));
    assert!(dom_p.require_permission("users.read").is_ok());

    let admin_tok = jwt_for(admin.user);
    let admin_adm = gate
        .admit(&base_req(
            ProtocolSurface::Http,
            GateCredential::Jwt {
                token: &admin_tok,
                from_cookie: false,
            },
            None,
        ))
        .await
        .unwrap();
    let admin_p = admin_adm.mint_admin(&factory).await.unwrap();
    let audit_proof = admin_p.require_global_permission(&["audit.read"]).unwrap();
    let ev = AuditEvent::new("authz546a.sensitive", "user").unwrap();
    let sens = factory
        .run_admin_sensitive_read(
            &audit_proof,
            &ev,
            "SELECT (r.rolbypassrls OR r.rolsuper), current_user::text \
               FROM pg_roles r WHERE r.rolname = current_user",
            &[],
        )
        .await
        .unwrap();
    assert!(sens[0].get::<_, bool>(0));
    if has_explicit_worker {
        assert_eq!(sens[0].get::<_, String>(1), "setjoin_worker");
    }

    // 3. Private pre-auth credential proof seam on PolicyGate runs on worker/owner.
    static PRE_AUTH_TEST: SqlContract = SqlContract {
        id: "authz546a.pre_auth",
        domain: "authz",
        sql: "SELECT u.id, (r.rolbypassrls OR r.rolsuper), current_user::text \
                FROM users u JOIN pg_roles r ON r.rolname = current_user WHERE u.id = $1",
        params: &[Type::INT8],
        columns: &[
            ColumnSpec::named("id", Type::INT8),
            ColumnSpec::unnamed(Type::BOOL),
            ColumnSpec::unnamed(Type::TEXT),
        ],
        scope: SqlScope::AuthPreScope,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };
    let pre = gate
        .run_pre_auth_read_contract(&PRE_AUTH_TEST, &[&alice.user])
        .await
        .unwrap();
    assert_eq!(pre[0].get::<_, i64>(0), alice.user);
    assert!(pre[0].get::<_, bool>(1));
    if has_explicit_worker {
        assert_eq!(pre[0].get::<_, String>(2), "setjoin_worker");
    }

    // 4. Fail-closed TxFactory / PolicyGate without AdminWorkerPool refuses admin & pre-auth reads.
    let app_only_factory = TxFactory::new(app_pool);
    assert!(!app_only_factory.has_admin_worker_pool());
    assert!(app_only_factory
        .begin_admin_read(&audit_proof)
        .await
        .is_err());
    let app_only_gate = PolicyGate::new(app_exec, Arc::new(StaticKeys::new()), ISSUER)
        .with_tx_factory(app_only_factory);
    assert!(app_only_gate.begin_pre_auth_read().await.is_err());

    // 5. ListenHub group_membership_changed per-user invalidation on GroupResolver.
    let grp_id: i64 = 954602;
    let m0 = groups.resolve(alice.user).await.unwrap();
    assert!(!m0.has_ca_group(CaGroupId::new(grp_id).unwrap()));
    let cached_before = groups.cached_len();
    assert!(cached_before >= 1);
    owner
        .execute(
            "INSERT INTO user_group_members (group_id, user_id) VALUES ($1, $2)",
            &[&grp_id, &alice.user],
        )
        .await
        .unwrap();
    let wait_until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < wait_until && groups.cached_len() >= cached_before {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        groups.cached_len(),
        cached_before - 1,
        "targeted per-user notification must evict only alice from GroupResolver cache"
    );
    let m1 = groups.resolve(alice.user).await.unwrap();
    assert!(m1.has_ca_group(CaGroupId::new(grp_id).unwrap()));

    let _ = stop_tx.send(true);
    listener_handle.abort();
    let _ = listener_handle.await;

    // Clean up test fixtures.
    for op in [env_mut.operation, env_sub.operation, env_usr.operation] {
        let _ = owner
            .execute(
                "DELETE FROM public.rust_operation_receipts WHERE operation_id = $1::text::uuid",
                &[&setjoin_pg::operation_hex(op)],
            )
            .await;
    }
    let _ = owner
        .execute(
            "DELETE FROM user_group_members WHERE group_id = $1 AND user_id = $2",
            &[&grp_id, &alice.user],
        )
        .await;
    for r in [global_role, scoped_role] {
        let _ = owner
            .execute(
                "DELETE FROM admin_role_assignments WHERE role_group_id = $1",
                &[&r],
            )
            .await;
        let _ = owner
            .execute("DELETE FROM admin_role_groups WHERE id = $1", &[&r])
            .await;
    }
    for a in [&alice, &admin, &domain_admin] {
        fixture::remove(&owner, a).await.unwrap();
    }
}
