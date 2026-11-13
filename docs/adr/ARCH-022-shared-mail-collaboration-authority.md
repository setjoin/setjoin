# ADR: ARCH-022 — Shared-mail collaboration authority

**Status:** Accepted
**Date:** 2026-08-11

## Context

Delegated mailboxes already expose Email content and send permissions, while Tasks,
Chat, Drive, push, and webhooks are separate systems. Putting claim state or private
notes in any one consumer would create split authority, leak internal context into
mail protocols, and make revocation/replay unreliable.

## Decision

Store shared-mail work, private comments, immutable events, shared-draft lease
metadata, and aggregate metrics in PostgreSQL under reducer authority. Scope work by
mailbox plus thread, reuse the existing delegated-mailbox access boundary, and use
transactional outboxes with dispatch-time authorization for every peripheral.

Email content remains under existing Email reducers. Draft collaboration stores a
stable session/revision/lease around that content rather than creating another body
store. Integrations receive bounded internal locators or approved opaque events,
never message/comment content.

## Consequences

- Gmail-style folder/tag changes cannot duplicate or orphan team work.
- Private comments are intentionally unavailable to ordinary mail protocols.
- Task/Chat/Drive/webhook outages cannot roll back an accepted work mutation;
  idempotent receipts and workers reconcile them.
- Analytics are useful only after cohort thresholds; individual performance
  scoring is deliberately unsupported.
- Enabling any component remains an explicit cohort rollout decision.
