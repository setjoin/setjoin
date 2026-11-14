//! Go's `parseAccountID` (handler.go:618) and the dispatch app gate (handler.go:1540).
use setjoin_contracts::ids::MailboxId;
use setjoin_pg::{MailboxAuthContext, Type};

use super::{Cx, Scope};
use crate::jmap::family::MethodError;

/// Resolve `accountId` exactly like Go: the caller's primary mailbox, or a
/// mailbox the caller holds a delegate grant on that this method's gate
/// admits, then the lifecycle gate. Every other case is `accountNotFound`
/// without an existence oracle.
pub(crate) async fn resolve(cx: &Cx<'_>, raw: &str) -> Result<Scope, MethodError> {
    if raw.is_empty() {
        return Err(MethodError::new("accountNotFound", "accountId is required"));
    }
    let Some(account) = raw.parse::<i64>().ok().filter(|id| *id > 0) else {
        return Err(MethodError::new("accountNotFound", "invalid accountId"));
    };
    let mismatch = || {
        MethodError::new(
            "accountNotFound",
            "accountId does not match authenticated user",
        )
    };
    // Go `identity.ValidateAccountID`: the primary is re-resolved on every call
    // (a WebSocket batch authorizes once). No primary falls through to the
    // delegate arm; a lookup failure fails closed.
    let rows = cx
        .exec
        .read(
            "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
            &[(&cx.user, Type::INT8)],
        )
        .await
        .map_err(|_| mismatch())?;
    let primary = match rows.first() {
        None => None,
        Some(row) => Some(row.try_get::<_, i64>(0).map_err(|_| mismatch())?),
    };
    let delegated = primary != Some(account);
    if delegated {
        // Go `delegateGrants`: user-scoped (FORCE RLS), per call, uncached.
        let rows = cx
            .exec
            .read_user_scoped(
                cx.primary.actor(),
                "SELECT permission::text FROM mailbox_delegates WHERE mailbox_id=$1 AND user_id=$2",
                &[(&account, Type::INT8), (&cx.user, Type::INT8)],
            )
            .await
            .map_err(|_| mismatch())?;
        let grants = rows
            .iter()
            .map(|row| row.try_get::<_, String>(0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| mismatch())?;
        if grants.is_empty() {
            return Err(mismatch());
        }
        if !cx.method.gate.allows(&grants) {
            return Err(MethodError::new(
                "forbidden",
                "insufficient delegate permission for this method",
            ));
        }
    }
    let allowed = cx
        .exec
        .read(
            "SELECT mailbox_lifecycle_access_allowed($1)",
            &[(&account, Type::INT8)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()));
    if allowed != Some(true) {
        return Err(MethodError::new(
            "forbidden",
            "mailbox access is suspended or detached",
        ));
    }
    let auth = MailboxAuthContext::from_authenticated_session(
        cx.primary.actor(),
        MailboxId::new(account).map_err(|_| mismatch())?,
        crate::jmap::REQUEST_AUTHORITY_GENERATION,
    );
    Ok(Scope {
        mailbox: account,
        auth,
        delegated,
    })
}

/// Go `PoolEntitlementChecker.Allowed`: fail closed; a denial writes Go's
/// best-effort `app_blocked` audit (no IP).
pub(super) async fn app_allowed(cx: &Cx<'_>) -> bool {
    let app = cx.method.app;
    let allowed = cx
        .exec
        .read(
            "SELECT check_user_app_entitlement($1,$2)",
            &[(&cx.user, Type::INT8), (&app, Type::TEXT)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()))
        == Some(true);
    if !allowed {
        if let Err(error) = cx
            .exec
            .audit_app_blocked_without_ip(cx.primary.actor(), app)
            .await
        {
            eprintln!(
                "setjoin-gateway: jmap app_blocked audit failed: sqlstate={}",
                error.sqlstate.as_deref().unwrap_or("none")
            );
        }
    }
    allowed
}

/// Runs on the server-rust lane (nextest profile `lane`, per-test clone,
/// REQUIRE_DB=1: `Db::for_case` panics there instead of skipping).
#[cfg(test)]
mod db {
    use futures_util::FutureExt;
    use setjoin_conformance::fixture::{self, Account};
    use setjoin_conformance::harness::Db;
    use setjoin_contracts::ids::{ActorId, Generation};
    use setjoin_pg::ScopedExecutor;
    use tokio_postgres::Client;

    use super::*;
    use crate::jmap::family::{always, Gate, Method, Reply};

    fn run_none<'a>(_: &'a Cx<'a>) -> Reply<'a> {
        Box::pin(async { Err(MethodError::server_fail()) })
    }

    const fn gate_method(name: &'static str, gate: Gate) -> Method {
        Method {
            name,
            capability: "urn:test",
            app: "",
            gate,
            account: true,
            mutator: false,
            state: false,
            ready: always,
            run: run_none,
        }
    }

    static GATES: [Method; 5] = [
        gate_method("Gate/personal", Gate::Personal),
        gate_method("Gate/read", Gate::Read),
        gate_method("Gate/mutate", Gate::Mutate),
        gate_method("Gate/submit", Gate::Submit),
        gate_method("Gate/collaborate", Gate::Collaborate),
    ];

    async fn grant(owner: &Client, mailbox: &Account, user: &Account, permission: &str) {
        owner
            .execute(
                "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES ($1, $2, $3, $4)",
                &[&mailbox.mailbox, &user.user, &permission, &mailbox.user],
            )
            .await
            .expect("grant");
    }

    async fn revoke(owner: &Client, mailbox: &Account) {
        owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = $1",
                &[&mailbox.mailbox],
            )
            .await
            .expect("revoke");
    }

    async fn set_suspended(owner: &Client, mailbox: i64, suspended: bool) {
        owner
            .execute(
                "UPDATE mailboxes SET enabled = $2 WHERE id = $1",
                &[&mailbox, &!suspended],
            )
            .await
            .expect("mailbox enabled");
        let state = if suspended { "suspended" } else { "active" };
        owner
            .execute(
                "UPDATE mailbox_lifecycle SET access_state = $2, generation = generation + 1, \
                 updated_at = statement_timestamp() \
                 WHERE mailbox_id = $1 AND binding_state IN ('bound','shared')",
                &[&mailbox, &state],
            )
            .await
            .expect("lifecycle access state");
    }

    async fn cases(db: &Db, owner: &Client, a: &Account, f: &Account, second: i64) {
        let exec =
            ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).expect("executor");
        let primary = MailboxAuthContext::from_authenticated_session(
            ActorId::new(a.user).expect("actor"),
            MailboxId::new(a.mailbox).expect("mailbox"),
            Generation(1),
        );
        let cx = |method: &'static Method| {
            Cx::new(&exec, None, &primary, a.user, a.mailbox, method, "{}")
        };
        let read = &GATES[1];
        let error = MethodError::new;
        let mismatch = error(
            "accountNotFound",
            "accountId does not match authenticated user",
        );
        let foreign = f.mailbox.to_string();

        assert_eq!(
            resolve(&cx(read), "").await.err(),
            Some(error("accountNotFound", "accountId is required"))
        );
        for raw in ["0", "-1", "abc"] {
            assert_eq!(
                resolve(&cx(read), raw).await.err(),
                Some(error("accountNotFound", "invalid accountId")),
                "{raw}"
            );
        }
        for raw in [
            a.mailbox.to_string(),
            format!("+{}", a.mailbox),
            format!("0{}", a.mailbox),
        ] {
            let scope = resolve(&cx(read), &raw).await.expect("own account");
            assert_eq!((scope.id(), scope.delegated()), (a.mailbox, false), "{raw}");
        }
        for method in &GATES {
            assert_eq!(
                resolve(&cx(method), &foreign).await.err(),
                Some(mismatch.clone()),
                "{} without a grant",
                method.name
            );
        }
        assert_eq!(
            resolve(&cx(read), &second.to_string()).await.err(),
            Some(mismatch.clone()),
            "non-primary own mailbox"
        );
        // The primary changes between calls: the former primary is no longer
        // owned (no grant: mismatch) and the new one is.
        owner
            .batch_execute(&format!(
                "BEGIN; SET LOCAL session_replication_role = replica; UPDATE mailboxes SET is_primary = FALSE WHERE id = {}; \
                 UPDATE mailboxes SET is_primary = TRUE WHERE id = {second}; COMMIT;",
                a.mailbox
            ))
            .await
            .expect("switch primary");
        assert_eq!(
            resolve(&cx(read), &a.mailbox.to_string()).await.err(),
            Some(mismatch.clone()),
            "former primary"
        );
        let scope = resolve(&cx(read), &second.to_string())
            .await
            .expect("new primary");
        assert_eq!((scope.id(), scope.delegated()), (second, false));
        owner
            .batch_execute(&format!(
                "BEGIN; SET LOCAL session_replication_role = replica; UPDATE mailboxes SET is_primary = FALSE WHERE id = {second}; \
                 UPDATE mailboxes SET is_primary = TRUE WHERE id = {}; COMMIT;",
                a.mailbox
            ))
            .await
            .expect("restore primary");

        for permission in [
            "read",
            "send_as",
            "send_on_behalf",
            "full_access",
            "manage_calendar",
        ] {
            grant(owner, f, a, permission).await;
            for method in &GATES {
                let outcome = resolve(&cx(method), &foreign).await;
                if method.gate.allows(&[permission.to_owned()]) {
                    let scope =
                        outcome.unwrap_or_else(|e| panic!("{} {permission}: {e:?}", method.name));
                    assert_eq!((scope.id(), scope.delegated()), (f.mailbox, true));
                } else {
                    assert_eq!(
                        outcome.err(),
                        Some(error(
                            "forbidden",
                            "insufficient delegate permission for this method"
                        )),
                        "{} {permission}",
                        method.name
                    );
                }
            }
            revoke(owner, f).await;
        }

        grant(owner, f, a, "read").await;
        let scope = resolve(&cx(read), &foreign).await.expect("delegated scope");
        let guc = super::super::call::read_unchecked(
            &cx(read),
            &scope,
            "SELECT current_setting('app.current_mailbox_id')",
        )
        .await
        .expect("scope GUC");
        assert_eq!(guc, foreign);
        revoke(owner, f).await;
        assert_eq!(
            resolve(&cx(read), &foreign).await.err(),
            Some(mismatch.clone()),
            "revoked grant"
        );

        grant(owner, f, a, "full_access").await;
        set_suspended(owner, f.mailbox, true).await;
        assert_eq!(
            resolve(&cx(read), &foreign).await.err(),
            Some(error(
                "forbidden",
                "mailbox access is suspended or detached"
            ))
        );
        set_suspended(owner, f.mailbox, false).await;
        revoke(owner, f).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_matches_parse_account_id() {
        let Some(db) = Db::for_case("resolve_matches_parse_account_id") else {
            return;
        };
        let owner = db.connect().await.expect("owner connection");
        let a = fixture::account(&owner, "famseam")
            .await
            .expect("own fixture");
        let f = fixture::account(&owner, "famseam-foreign")
            .await
            .expect("foreign fixture");
        let second: i64 = owner
            .query_one(
                "INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary) \
                 SELECT id, domain_id, 'second-' || email, 'second', 'personal', FALSE \
                 FROM users WHERE id = $1 RETURNING id",
                &[&a.user],
            )
            .await
            .expect("second mailbox")
            .get(0);
        let outcome = std::panic::AssertUnwindSafe(cases(&db, &owner, &a, &f, second))
            .catch_unwind()
            .await;
        let _ = owner
            .batch_execute(&format!(
                "BEGIN; SET LOCAL session_replication_role = replica; UPDATE mailboxes SET is_primary = FALSE WHERE id = {second}; \
                 UPDATE mailboxes SET is_primary = TRUE WHERE id = {}; COMMIT;",
                a.mailbox
            ))
            .await;
        let _ = owner
            .execute(
                "UPDATE mailboxes SET enabled = true WHERE id = ANY($1)",
                &[&vec![a.mailbox, f.mailbox]],
            )
            .await;
        let _ = owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = ANY($1)",
                &[&vec![a.mailbox, f.mailbox, second]],
            )
            .await;
        let _ = owner
            .batch_execute(&format!(
                "BEGIN; SET LOCAL session_replication_role=replica; \
                 DELETE FROM mailbox_audit_log WHERE mailbox_id={second}; COMMIT;"
            ))
            .await;
        let _ = owner
            .execute("DELETE FROM mailboxes WHERE id = $1", &[&second])
            .await;
        fixture::remove(&owner, &f).await.expect("remove foreign");
        fixture::remove(&owner, &a).await.expect("remove own");
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
}

#[cfg(test)]
mod offline {
    use setjoin_contracts::ids::{ActorId, Generation};
    use setjoin_pg::ScopedExecutor;

    use super::*;
    use crate::jmap::family::{always, Gate, Method, Reply};

    fn run_none<'a>(_: &'a Cx<'a>) -> Reply<'a> {
        Box::pin(async { Err(MethodError::server_fail()) })
    }

    static READ: Method = Method {
        name: "Gate/read",
        capability: "urn:test",
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: run_none,
    };

    /// The authorized mailbox alone is not ownership: an unreadable primary fails closed.
    #[tokio::test]
    async fn a_failed_primary_lookup_fails_closed() {
        let exec = ScopedExecutor::from_dsn("host=127.0.0.1 port=1 user=x dbname=x", 1)
            .expect("lazy pool");
        let primary = MailboxAuthContext::from_authenticated_session(
            ActorId::new(1).expect("actor"),
            MailboxId::new(2).expect("mailbox"),
            Generation(1),
        );
        let cx = Cx::new(&exec, None, &primary, 1, 2, &READ, "{}");
        assert_eq!(
            resolve(&cx, "2").await.err(),
            Some(MethodError::new(
                "accountNotFound",
                "accountId does not match authenticated user"
            ))
        );
    }
}
