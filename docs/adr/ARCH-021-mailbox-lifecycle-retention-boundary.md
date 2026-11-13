# ADR: ARCH-021 — Mailbox lifecycle and retention boundary

**Status:** Accepted
**Date:** 2026-08-11

## Context

Setjoin historically coupled user removal and mailbox deletion too closely. That
made ordinary identity-source changes, employee departure, mistaken deletion, and
legal retention hard to distinguish. Exchange-style Disable/Enable naming would
also permit an enable action to create a different mailbox implicitly, which is
unsafe for identity continuity and audit evidence.

## Decision

Create a reducer-authoritative mailbox lifecycle with explicit suspend,
detach-retain, reconnect, create-new, and delayed permanently-purge operations.
Retained mailboxes keep their IDs, content, addresses, aliases, and evidence.
Reconnect requires a locked, versioned stable-identity proof. Permanent purge is
independently approved and fail-closed over a registered blocker set.

Ordinary identity-source transitions preserve `users.id` and mailbox IDs. They
change verified source links through the identity transition authority and never
detach a mailbox as an intermediate step.

## Consequences

- Administrators get more explicit verbs and a preview/receipt workflow.
- Address reuse is delayed until a successful permanent purge.
- Post-write rollback is forward-only; accepted evidence is retained.
- Later mailbox-scoped domains must register a purge blocker before their writes
  can be enabled.
- Shared/resource/room/equipment/Guest authorities remain outside v1 rather than
  being inferred from a nullable `user_id`.

## Rejected alternatives

- Reproducing Disable-Mailbox/Enable-Mailbox side effects.
- Matching reconnect targets by email, UPN, display name, or username alone.
- Letting user/source deletion synchronously purge mailbox content.
- Providing a legal-hold bypass or treating sidecar cleanup as purge authority.
