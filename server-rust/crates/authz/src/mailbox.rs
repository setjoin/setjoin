//! Live shared-mailbox mail-read authority, matching Go's gateRead.
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

/// A verified member can read its primary account or an account with any mail
/// delegate grant. Calendar-only grants do not admit mail. Never cache this
/// answer: revocation must affect the next request. The target is a selector;
/// the actor and primary mailbox come exclusively from verified admission.
pub async fn can_read(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    target: i64,
) -> Result<bool, StatementFailure> {
    if target == auth.mailbox().get() {
        return Ok(true);
    }
    if target <= 0 {
        return Ok(false);
    }
    let actor = auth.actor();
    let user = actor.get();
    // mailbox_delegates is FORCE-RLS. Go's RunUserScoped sets this same GUC;
    // the authenticated user predicate remains mandatory on every credential.
    let rows=exec.read_user_scoped(actor,
        "SELECT EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=$1 AND user_id=$2 AND permission IN ('read','send_as','send_on_behalf','full_access'))",
        &[(&target,Type::INT8),(&user,Type::INT8)]).await?;
    Ok(rows.first().is_some_and(|row| row.get(0)))
}
