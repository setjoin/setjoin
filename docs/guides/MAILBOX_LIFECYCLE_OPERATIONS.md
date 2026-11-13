# Mailbox lifecycle operations

The lifecycle feature is OFF by default. Before any canary, run
`bash scripts/verify-mailbox-lifecycle.sh quick`, confirm the parity report has
no conflicts, and test with a disposable mailbox.

Use explicit verbs: **suspend** keeps the user binding and blocks access;
**detach and retain** removes the user binding while reserving every address;
**reconnect** requires a stable identity proof; **purge** is a separately
approved delayed action. Creating a new mailbox is never an implicit side
effect of resume or reconnect.

Every mutation requires an idempotency UUID, an exact generation, and an audit
reason. A stale generation or changed identity proof requires a new preview.
Purge remains blocked by retention, legal hold, WORM, shared-reference, and
registered-domain predicates. Never bypass a blocker with direct SQL.

Recovery order is: inspect the immutable receipt, refresh current state, retry
the same request only when its input is identical, otherwise issue a new
idempotency key. Cancel a pending purge before reconnecting. Production rollout
and feature enablement are separate operator decisions.
