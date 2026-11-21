//! Non-Family and shared JMAP `accountId` resolution (#356, Go `handler.go:618-694`).
//!
//! Resolves `accountId` against the caller's primary mailbox or an explicit
//! `mailbox_delegates` grant (queried under `app.current_user_id` for V090
//! FORCE-RLS), enforces the per-method [`Gate`] class, and verifies
//! `mailbox_lifecycle_access_allowed`.

use setjoin_contracts::ids::{ActorId, MailboxId};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, Type};

use super::family::Gate;
use super::{PRECHECK_TIMEOUT, REQUEST_AUTHORITY_GENERATION};

pub(crate) struct ResolvedAccount {
    pub mailbox: i64,
    pub auth: MailboxAuthContext,
    pub delegated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountError {
    pub kind: &'static str,
    pub detail: &'static str,
}

impl AccountError {
    pub(crate) fn status(&self) -> u16 {
        super::family::error_status(self.kind)
    }

    pub(crate) fn json(&self) -> String {
        crate::problem::jmap(self.status(), self.kind, self.detail)
    }
}

/// Resolve `accountId` like Go's `parseAccountID`: primary mailbox or a
/// delegated mailbox admitting `gate`, then `mailbox_lifecycle_access_allowed`.
pub(crate) async fn resolve_account(
    exec: &ScopedExecutor,
    user_id: i64,
    raw: &str,
    gate: Gate,
) -> Result<ResolvedAccount, AccountError> {
    if raw.is_empty() {
        return Err(AccountError {
            kind: "accountNotFound",
            detail: "accountId is required",
        });
    }
    let Some(account) = raw.parse::<i64>().ok().filter(|id| *id > 0) else {
        return Err(AccountError {
            kind: "accountNotFound",
            detail: "invalid accountId",
        });
    };
    let mismatch = || AccountError {
        kind: "accountNotFound",
        detail: "accountId does not match authenticated user",
    };
    let actor = ActorId::new(user_id).map_err(|_| mismatch())?;

    // Go `identity.ValidateAccountID`: re-read primary mailbox on every call.
    let rows = tokio::time::timeout(
        PRECHECK_TIMEOUT,
        exec.read(
            "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
            &[(&user_id, Type::INT8)],
        ),
    )
    .await
    .map_err(|_| mismatch())?
    .map_err(|_| mismatch())?;
    let primary = match rows.first() {
        None => None,
        Some(row) => Some(row.try_get::<_, i64>(0).map_err(|_| mismatch())?),
    };
    let delegated = primary != Some(account);
    if delegated {
        // V090 FORCE-RLS: mailbox_delegates requires app.current_user_id scope.
        let rows = tokio::time::timeout(
            PRECHECK_TIMEOUT,
            exec.read_user_scoped(
                actor,
                "SELECT permission::text FROM mailbox_delegates WHERE mailbox_id=$1 AND user_id=$2",
                &[(&account, Type::INT8), (&user_id, Type::INT8)],
            ),
        )
        .await
        .map_err(|_| mismatch())?
        .map_err(|_| mismatch())?;
        let grants = rows
            .iter()
            .map(|row| row.try_get::<_, String>(0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| mismatch())?;
        if grants.is_empty() {
            return Err(mismatch());
        }
        if !gate.allows(&grants) {
            return Err(AccountError {
                kind: "forbidden",
                detail: "insufficient delegate permission for this method",
            });
        }
    }
    let allowed = tokio::time::timeout(
        PRECHECK_TIMEOUT,
        exec.read(
            "SELECT mailbox_lifecycle_access_allowed($1)",
            &[(&account, Type::INT8)],
        ),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .and_then(|rows| rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()));
    if allowed != Some(true) {
        return Err(AccountError {
            kind: "forbidden",
            detail: "mailbox access is suspended or detached",
        });
    }
    let auth = MailboxAuthContext::from_authenticated_session(
        actor,
        MailboxId::new(account).map_err(|_| mismatch())?,
        REQUEST_AUTHORITY_GENERATION,
    );
    Ok(ResolvedAccount {
        mailbox: account,
        auth,
        delegated,
    })
}
