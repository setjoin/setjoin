# Rules and rule templates (F09, #329)

Frozen Go is the behaviour contract (ARCH-029/030). `rules.go`, `user_rules.go`
and `admin_templates.go` are the reference; all 21 registrations mount at `/api`.
The HTTP seam and committed effects are tested by gateway target `rules`, using
immutable Go observations under `tests/conformance/rules/goldens`.

Personal rules take the actor and primary mailbox only from authenticated context;
reads and mutations constrain ownership and refuse transport rules. Admin rule
routes require live console/pipeline grants and org-wide authority. Templates are
org-wide governance data: their admin routes require the same live grants, while
the personal list applies enabled/per-user visibility filtering.

The source map's claim that Rules has no reducers predates the frozen tree:
`rule_config_create|update|delete|template_create` already own the admin writes.
Reuse their exact effects; do not add state bumps or notifications absent in Go.

Personal create is Go's single INSERT in a scoped, receipted command. It forces
the authenticated primary mailbox and `is_transport_rule=false`, keeps Go's
100-rule admission read, and emits no audit/state/notification. Decode preserves
field folding, duplicate/null semantics and raw program bytes; personal programs
are capped at 16 KiB/20 entries, names at 200 UTF-8 bytes, body at 64 KiB.
Personal update/delete keep the authenticated user in the mutation predicate and
exclude transport rules. Update retains Go's zero-value overwrites for omitted
scalars; absent programs retain their stored values. Explicit JSON null programs
are jsonb null. The foreign mailbox and transport fields in requests are ignored.
Retro apply reuses `rules_apply_retroactive` with the verified primary mailbox.
It keeps Go's separate three-active-sweep admission read, dedup behavior and typed
problem bodies (including the 429 title). Scheduler execution belongs to the
already ported scheduled-actions dispatcher; F09 adds no worker or cron task.

Admin create/update/delete call the frozen `rule_config_*` reducers in receipted
commands, preserving their atomic audit rows and actor-containment predicates.
Read routes and dry-run use the worker credential after the org-wide gate.
Go's dry-run always fails its prepared `SET LOCAL; SELECT` batch with 42601;
valid rule requests therefore remain 500, missing rules 404. No evaluator rewrite.
On live authority-resolution failure frozen Go retained the verified JWT's signed
grants; owner-approved security fix 2026-11-05 (#484) drops them (`authority::lookup_failed`,
fail closed). Personal-rule and sweep caps (100 / 3) are enforced in the database:
`setjoin_pg::run_receipted_command_capped` locks the mailbox row FOR UPDATE, then counts and
writes as separate statements of one transaction (Go counted unlocked, so concurrent requests
exceeded the caps); `personal_create`/`apply` answer `Committed("cap")` when full. Tests: gateway `secfix3_rules`; mutants via `scripts/test-secfix3-mutants.py`.

The active schema omits both template tables. `tests/conformance/rules/legacy-fixture.sql`
is temporary oracle data only, never a schema migration or archive load. Template
qualification covers both explicit legacy fixtures and the unchanged schema's failures.

Template reads and writes use the request credential after live console/pipeline
admission. Unlike rule administration, Go allows domain-scoped template admins.
List/get/resolve preserve raw jsonb key order; list retains only rows before
the first scan failure (including a NULL description), and get maps any
read/scan failure to 404. Resolve requires enabled=true.
Create is a single INSERT and ignores the request's enabled pointer (DB default
true). Update is a single statement: absent description clears it, while absent
name/category/programs/optional enabled/sort retain their stored values. System
rows remain mutable like Go. These direct template writes emit no audit/state/notify.
Delete retains Go's system-row refusal and FK-cascaded visibility deletion.
Visibility uses the nullable target user (NULL = global override): one upsert or
one null-safe delete, always 204 on an acknowledged success. Personal template
list filters only the authenticated user's hidden rows; Go ignores global hidden
rows there. Template instantiation substitutes complete quoted placeholders,
resolves the authenticated primary mailbox, and calls `rule_config_template_create`
with its audit row. Parameter-map iteration order remains unspecified like Go.

The qualification corpus and recording workflow are documented in
[`tests/conformance/rules/README.md`](../../../tests/conformance/rules/README.md).
All 21 routes have ownership/invalid-input observations and status mutants;
mutators additionally cover repeated requests, every mailbox state counter and
row companions. Family audit/state/tenant mutants change real observed effects.
Before/after COMMIT cuts must return an operation ID and resolve its durable
receipt, with all effects respectively absent or identical to the Go recording.
No F09 handler emits a notification in Go; inventing one would violate parity.
Common admission still forwards unported security shapes owned by #349–#352;
there is no F09 back-to-Go flag or alternate native error fallback.
