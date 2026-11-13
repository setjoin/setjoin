//! Authenticated mailbox scope. The only source of the transaction's tenant key.
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    ids::{ActorId, Generation, MailboxId},
};
use std::sync::Arc;

/// The mailbox a request is authenticated for, produced by the session/auth
/// layer from verified credentials. Request-owned identity fields (a JMAP
/// `accountId`, `SetMessageSeen::mailbox`, a URL segment) are never passed
/// here: they are compared against this context, not used to build it (R2).
///
/// The executor derives the transaction-local `app.current_mailbox_id` GUC
/// and the lifecycle's current [`AuthorityKey`] from this value alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxAuthContext {
    actor: ActorId,
    mailbox: Option<MailboxId>,
    generation: Generation,
    pub(crate) audit_keys: Option<Arc<AuditKeys>>,
}

impl MailboxAuthContext {
    /// Call only from the authentication boundary with values read from the
    /// verified session (the Go equivalent is the authenticated primary
    /// mailbox `parseAccountID` resolves, ARCH-003).
    pub fn from_authenticated_session(
        actor: ActorId,
        mailbox: MailboxId,
        generation: Generation,
    ) -> Self {
        Self {
            actor,
            mailbox: Some(mailbox),
            generation,
            audit_keys: None,
        }
    }

    /// User-scoped domains must not invent a mailbox for active guests.
    pub fn from_authenticated_user(actor: ActorId, generation: Generation) -> Self {
        Self { actor, mailbox: None, generation, audit_keys: None }
    }

    pub fn mailbox_optional(&self) -> Option<MailboxId> { self.mailbox }

    pub fn actor(&self) -> ActorId {
        self.actor
    }

    pub fn mailbox(&self) -> MailboxId {
        self.mailbox.expect("mailbox operation requires real mailbox authority")
    }

    /// The current authority key the lifecycle compares the envelope against.
    pub fn authority(&self) -> AuthorityKey {
        AuthorityKey {
            actor: self.actor,
            scope: self.mailbox.map_or(ResourceScope::User(self.actor), ResourceScope::Mailbox),
            generation: self.generation,
        }
    }
}

/// Trusted deployment secrets, attached only by the executor to a verified
/// mailbox context. Never decoded from token claims, request bodies or headers.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuditKeys {
    pub encryption: String,
    pub audit_hmac: String,
}
impl std::fmt::Debug for AuditKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditKeys([redacted])")
    }
}
