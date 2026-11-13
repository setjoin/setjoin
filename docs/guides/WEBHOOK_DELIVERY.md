# Webhook delivery and scope

Webhook subscriptions have an explicit scope:

- Self-service `/auth/me/webhooks` always creates `self`.
- Privileged `/admin/webhooks` may explicitly create `self` or `organization`.
- Every subscription created before V211 is migrated to `self`. An operator who
intended organization-wide delivery must review and recreate that subscription
with `organization`; Setjoin does not broaden old rows automatically.
Generic events without an authenticated subject are delivered only to explicit
`organization` subscriptions. A `self` row is never treated as broad merely
because an older event caller has not yet migrated to a typed subject seam.

`feature.webhook_publication_outbox` defaults OFF. OFF preserves the post-commit
legacy typed paths, scope-matched to the reducer-derived subject. ON currently
enrolls `user.created`, `user.updated`, `user.deleted`, `migration.completed`,
and `migration.failed` as stable facts in the same database transaction as the
owning mutation. User facts carry only `user_id`; migration facts carry only
`job_id`. Legacy `user.created` retains its historical `email` and `created_by`
fields while the flag is OFF; those fields are intentionally not approved for
the durable fact. The flag controls new enrollment only: turning it OFF never
stops the unconditional worker from draining facts that already committed.

The drain uses a fixed eight-worker executor with eight queued slots. A delivery
enters memory only after a worker-owned database claim leases one of those 16
slots using `SKIP LOCKED`; unclaimed rows retain fair `(next_attempt_at,id)`
ordering. Circuit-open and HTTP failures are durably settled to retry/exhausted
state, and an expired in-flight lease consumes the subscription's total attempt
budget. The 45-second lease exceeds the 30-second HTTP and five-second settlement
bounds. Shutdown drains only work admitted before lifecycle cancellation.

Migration facts use mailbox audience only when the reducer proves the target
mailbox belongs to the migration job's user. Missing or mismatched mailbox
ownership falls back to the user audience; the generic worker never infers a
subject from payload JSON.

Publication facts contain no endpoint URL or signing secret. At drain time, SQL
matches the current active subscription, event type, scope and reducer-derived
subject, then creates one logical delivery row per `(subscription,event)`.
Deleting, disabling or revoking a subscription before drain prevents delivery.

Transport is at-least-once. A crash after the receiver accepts HTTP but before
Setjoin persists the result can resend the same CloudEvent. Receivers must retain
and deduplicate the stable CloudEvent `id`; they must not assume one HTTP request.
Endpoint outages do not roll back the accepted business mutation.

Verify locally with:

```bash
bash scripts/verify-architecture-r3.sh --doctor
bash scripts/verify-architecture-r3.sh webhook-outbox
```
