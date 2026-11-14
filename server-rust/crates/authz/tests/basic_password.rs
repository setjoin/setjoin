//! #355-0: the shared protocol password check against the assigned database.
use futures_util::FutureExt;
use setjoin_authz::basic::{
    self, Accept, GuestAppPasswords, PasswordCache, Policy, TotpAccountPassword, Verdict, Verified,
};
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};

const PASSWORD: &str = "basic355-Account-Password1";
const NEW_PASSWORD: &str = "basic355-New-Password2";
const APP_TOKEN: &str = "basic355-app-token-valid";

/// Go's auth.CheckPassword (LDAP-style; TOTP admitted as frozen Go does).
const ACCOUNT: Policy = Policy {
    accept: Accept::AccountPassword,
    guest_app_passwords: GuestAppPasswords::Refuse,
    totp_account_password: TotpAccountPassword::Admit,
};
/// DAV Basic (#355a owner decision).
const DAV: Policy = Policy {
    accept: Accept::AppPassword,
    guest_app_passwords: GuestAppPasswords::Refuse,
    totp_account_password: TotpAccountPassword::Refuse,
};
/// IMAP (owner ruling F1: TOTP account password refused).
const IMAP: Policy = Policy {
    accept: Accept::AppPasswordThenAccountPassword,
    guest_app_passwords: GuestAppPasswords::Admit,
    totp_account_password: TotpAccountPassword::Refuse,
};

fn bcrypt_hash(password: &str, cost: u32) -> String {
    bcrypt::hash_with_result(password, cost)
        .unwrap()
        .format_for_version(bcrypt::Version::TwoA)
}

fn token_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn shared_password_check_follows_go_and_the_explicit_policy() {
    let Some(db) = Db::for_case("basic355-shared-password") else {
        return;
    };
    let c = db.connect().await.unwrap();
    let account = fixture::account(&c, "basic355").await.unwrap();
    let user = account.user;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&user])
        .await
        .unwrap()
        .get(0);
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    let outcome = std::panic::AssertUnwindSafe(async {
        let verified = Verified { user_id: user, email: email.clone() };
        let low = bcrypt_hash(PASSWORD, 4);
        c.execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&low, &user]).await.unwrap();
        let cache = PasswordCache::new();

        // 1. Account password on a below-floor hash: verified, self-healed, cached, no audit row.
        assert_eq!(basic::verify(&exec, &cache, &email, PASSWORD, ACCOUNT).await, Verdict::AccountPassword(verified.clone()));
        let healed: String = c.query_one("SELECT password_hash FROM users WHERE id=$1", &[&user]).await.unwrap().get(0);
        assert_ne!(healed, low);
        assert!(healed.starts_with("$2a$10$"), "{healed}");
        assert!(bcrypt::verify(PASSWORD, &healed).unwrap());
        assert_eq!(cache.len(), 1);
        let rows: i64 = c.query_one("SELECT count(*) FROM auth_event_log WHERE user_id=$1 OR lower(email)=lower($2)", &[&user, &email]).await.unwrap().get(0);
        assert_eq!(rows, 0, "account-only verification writes no audit row");

        // 2. Wrong password: refused and never cached.
        assert_eq!(basic::verify(&exec, &cache, &email, "wrong", ACCOUNT).await, Verdict::Refused);
        assert_eq!(cache.len(), 1);

        // 3. Repeat within the TTL: the second call is a hit (no new entry).
        for _ in 0..2 {
            assert_eq!(basic::verify(&exec, &cache, &email, PASSWORD, ACCOUNT).await, Verdict::AccountPassword(verified.clone()));
            assert_eq!(cache.len(), 2);
        }

        // 4. Admin reset: the old password stops working at once despite the cache.
        let reset = bcrypt_hash(NEW_PASSWORD, 4);
        c.execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&reset, &user]).await.unwrap();
        assert_eq!(basic::verify(&exec, &cache, &email, PASSWORD, ACCOUNT).await, Verdict::Refused);
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, ACCOUNT).await, Verdict::AccountPassword(verified.clone()));

        // 5. A disabled account is refused even with a cached entry.
        c.execute("UPDATE users SET enabled=false WHERE id=$1", &[&user]).await.unwrap();
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, ACCOUNT).await, Verdict::Refused);
        c.execute("UPDATE users SET enabled=true WHERE id=$1", &[&user]).await.unwrap();

        // 6. F1 owner ruling: TOTP user's account password refused on IMAP and DAV,
        //    including on a warm cache; app passwords still accepted.
        c.execute("INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'basic355','basic355',$2)", &[&user, &token_hash(APP_TOKEN)]).await.unwrap();
        for _ in 0..2 {
            assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, IMAP).await, Verdict::AccountPassword(verified.clone()));
        }
        let warm = cache.len();
        assert!(warm >= 1);
        c.execute("UPDATE users SET totp_enabled=true WHERE id=$1", &[&user]).await.unwrap();
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, IMAP).await, Verdict::Refused);
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, DAV).await, Verdict::Refused);
        assert_eq!(cache.len(), warm, "the TOTP refusal does no hash work and adds no entry");
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, ACCOUNT).await, Verdict::AccountPassword(verified.clone()), "explicit Go-parity policy still admits");
        assert_eq!(basic::verify(&exec, &cache, &email, APP_TOKEN, IMAP).await, Verdict::AppPassword(verified.clone()));
        assert_eq!(basic::verify(&exec, &cache, &email, APP_TOKEN, DAV).await, Verdict::AppPassword(verified.clone()));
        c.execute("UPDATE users SET totp_enabled=false WHERE id=$1", &[&user]).await.unwrap();

        // 7. Guests: account password refused even with a cached entry; app
        //    passwords refused or admitted by explicit policy.
        c.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,'guest@test','inviter@test',$2,'active')", &[&user, &account.domain]).await.unwrap();
        c.execute("UPDATE app_passwords SET last_used_at=NULL WHERE user_id=$1", &[&user]).await.unwrap();
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, ACCOUNT).await, Verdict::Refused);
        assert_eq!(basic::verify(&exec, &cache, &email, APP_TOKEN, DAV).await, Verdict::Refused);
        let untouched: bool = c.query_one("SELECT last_used_at IS NULL FROM app_passwords WHERE user_id=$1", &[&user]).await.unwrap().get(0);
        assert!(untouched);
        assert_eq!(basic::verify(&exec, &cache, &email, APP_TOKEN, IMAP).await, Verdict::AppPassword(verified.clone()));
        c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&user]).await.unwrap();

        // 8. App-password-only (DAV) never falls back to the account password.
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, DAV).await, Verdict::Refused);
        // 9. Account-password-only never accepts an app password.
        assert_eq!(basic::verify(&exec, &cache, &email, APP_TOKEN, ACCOUNT).await, Verdict::Refused);
        // 10. IMAP order: the account password after the app-password failure row.
        assert_eq!(basic::verify(&exec, &cache, &email, NEW_PASSWORD, IMAP).await, Verdict::AccountPassword(verified.clone()));

        // 11. App password: case-insensitive email, bookkeeping, one success row without IP; never cached.
        c.execute("DELETE FROM auth_event_log WHERE user_id=$1 OR lower(email)=lower($2)", &[&user, &email]).await.unwrap();
        c.execute("UPDATE app_passwords SET last_used_at=NULL WHERE user_id=$1", &[&user]).await.unwrap();
        let before = cache.len();
        let shouted = email.to_uppercase();
        assert_eq!(basic::verify(&exec, &cache, &shouted, APP_TOKEN, DAV).await, Verdict::AppPassword(verified.clone()));
        assert_eq!(cache.len(), before, "app passwords never enter the cache");
        let used: bool = c.query_one("SELECT last_used_at IS NOT NULL FROM app_passwords WHERE user_id=$1", &[&user]).await.unwrap().get(0);
        assert!(used);
        let events: Vec<(Option<i64>, String, String, bool)> = c
            .query("SELECT user_id, event, provider, ip_address IS NULL FROM auth_event_log WHERE email=$1 ORDER BY id", &[&shouted])
            .await.unwrap().iter().map(|r| (r.get(0), r.get(1), r.get(2), r.get(3))).collect();
        assert_eq!(events, vec![(Some(user), "login".to_owned(), "app_password".to_owned(), true)]);

        // 12. F5: an app password that expires right after a successful use is refused at once.
        c.execute("UPDATE app_passwords SET expires_at=now()-interval '1 second' WHERE user_id=$1", &[&user]).await.unwrap();
        assert_eq!(basic::verify(&exec, &cache, &shouted, APP_TOKEN, DAV).await, Verdict::Refused);
        c.execute("UPDATE app_passwords SET expires_at=NULL WHERE user_id=$1", &[&user]).await.unwrap();

        // 13. A revoked app password is refused with a failure row without a user.
        c.execute("UPDATE app_passwords SET revoked_at=now() WHERE user_id=$1", &[&user]).await.unwrap();
        assert_eq!(basic::verify(&exec, &cache, &shouted, APP_TOKEN, DAV).await, Verdict::Refused);
        let last: (Option<i64>, String) = {
            let r = c.query_one("SELECT user_id, event FROM auth_event_log WHERE email=$1 ORDER BY id DESC LIMIT 1", &[&shouted]).await.unwrap();
            (r.get(0), r.get(1))
        };
        assert_eq!(last, (None, "login_failed".to_owned()));

        // 14. The self-heal CAS loses to a concurrent rotation.
        let current: String = c.query_one("SELECT password_hash FROM users WHERE id=$1", &[&user]).await.unwrap().get(0);
        exec.upgrade_legacy_protocol_password(user, &email, "stale-hash", &bcrypt_hash(PASSWORD, 4)).await.unwrap();
        let after: String = c.query_one("SELECT password_hash FROM users WHERE id=$1", &[&user]).await.unwrap().get(0);
        assert_eq!(after, current);

        // 15. record_event maps an empty email/IP to NULL.
        basic::record_event(&exec, Some(user), "login", "basic", "", Some("")).await;
        let basic_rows: i64 = c.query_one("SELECT count(*) FROM auth_event_log WHERE user_id=$1 AND provider='basic' AND email IS NULL AND ip_address IS NULL", &[&user]).await.unwrap().get(0);
        assert_eq!(basic_rows, 1);

        // 16. A database failure fails closed.
        let broken = setjoin_pg::ScopedExecutor::from_dsn(&format!("{}?options=-csearch_path%3Dpg_catalog", db.dsn), 1).unwrap();
        assert_eq!(basic::verify(&broken, &PasswordCache::new(), &email, NEW_PASSWORD, ACCOUNT).await, Verdict::Refused);
    })
    .catch_unwind()
    .await;
    c.execute(
        "DELETE FROM auth_event_log WHERE user_id=$1 OR lower(email)=lower($2)",
        &[&user, &email],
    )
    .await
    .unwrap();
    c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&user])
        .await
        .unwrap();
    fixture::remove(&c, &account).await.unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
