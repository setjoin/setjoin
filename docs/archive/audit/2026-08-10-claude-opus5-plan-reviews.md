# Claude Opus 5 second-voice plan reviews — 2026-08-10

## Scope and invocation

Claude Code was invoked directly from the repository root with exact model
`claude-opus-5`, `xhigh` effort, disabled slash commands, prompt-enforced
read-only repository access, and no secrets/customer/production evidence. Codex
completed its own analysis before every prompt.

## Mailbox Lifecycle & Retention

The first retry completed only a partial review. It independently confirmed:

- nullable `mailboxes.user_id` with `ON DELETE SET NULL`;
- the direct BYPASSRLS Go deletion cascade;
- destructive immediate admin UI copy;
- in-place identity transition preserving `users.id` and mailbox rows;
- schema head V194 and the plan's deferred migration numbering.

It found one additional defect: `admin_users.go` dispatches `EventUserDeleted`
before the surrounding transaction commits, allowing a rollback to emit deletion
for a user that still exists. Accepted correction: the lifecycle plan now requires
a transaction-bound durable outbox and a rollback/no-webhook regression test.

Claude explicitly withheld a score because it had not finished approval, BZ,
address, delivery, retention and test-contract checks. A focused continuation ran
for the bounded window without output and was stopped. No Claude final score is
claimed.

## Webmail Competitive Productivity Roadmap

Claude reviewed only four high-risk boundaries after Codex's full Autoplan pass and
returned **6.5/10 before corrections**. All twelve findings were accepted:

| Finding | Disposition |
| --- | --- |
| F1 shared mailboxes lack the `users.id` key used by Focus/VIP/safe/block | P0-B made personal-mailbox-only; delegated control hidden; shared mailbox policy deferred to a new spec |
| F2 plain-read delegates could read/be mentioned but not comment | Explicit view-only semantics/copy; comment writers are send-capable delegates |
| F3 NULL-owner shared mailboxes have no owner fallback | Privileged assignment/policy/analytics/lease break requires `full_access` or an authorized admin surface |
| F4 locked table still named rejected Thread-state reuse | Corrected to independent `jmap_mailwork_state`/journal with unchanged eight-part session token |
| F5 work-only state does not advance composite session state | Added push plus bounded polling and positive byte-compatibility/convergence test |
| F6 send creates a fresh Email and uses BYPASSRLS | Collaborative flow now submits the session's current tuple and requires explicit mailbox/user/grant/session CAS |
| F7 send reducer signatures lacked session/revision | M7 explicitly extends JMAP/submission/send with backward-compatible optional parameters and stale-revision pgTAP |
| F8 trash-first draft retirement could expose intermediate drafts | Collaborative prior drafts use internal physical retirement; revision evidence remains private |
| F9 full sender-list replacement had no concurrency token | Added generation/ETag/If-Match and per-sender mutations |
| F10 NeverBlock could partially delete then fail to safelist | Marked as a defect to remove during reducer migration |
| F11 report lacked idempotency | Added operation UUID and one dedupe boundary for audit and feedback outbox |
| F12 report accepted arbitrary numeric target ID | Added server resolution plus reducer-side R1 ownership validation |

A correction-only Claude run was requested after these edits. It produced no output
within the bounded window and ended with `Execution error`; therefore no post-fix
Claude score is claimed. Codex rechecked every correction against the cited source
and retains its own 10/10 plan-completeness verdict. Claude unavailability remains
non-blocking under project policy.

No finding challenged a user-confirmed product decision after the accepted P0-B
scope narrowing. No repository file was modified by Claude.

## Final implementation-review attempts

After Codex completed the V195–V204 implementation and deterministic gates, it
invoked exact `claude-opus-5` at `xhigh` twice in prompt-enforced read-only mode.
The first review covered the bounded three-program diff; the second narrowed to
V199/V200/V204 mailbox lifecycle and source-to-source identity execute/rollback.
Each process remained alive without producing any output or review artifact for
20 minutes and was stopped. Both ended with `Execution error`. Neither attempt is
counted as approval, a clean review, or a score. The earlier successful Fable 5
portfolio review remains the independent plan-discovery evidence; Codex's tests
and final synthesis remain primary. No file was modified by Claude.
