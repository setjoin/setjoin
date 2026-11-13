# ADR: ARCH-008 — Defer the client-side JMAP "sync ledger"; full-reload-on-token is the intended sound baseline

**Status:** Accepted (as a deferral)
**Date:** 2026-06-19
**Source:** Webmail architecture review (`/improve-codebase-architecture` over `mailserver/webmail/src/`) → candidate **sync-ledger** → adversarial validate/refute + `/grill-with-docs` 2026-06-19. Recorded so a future review does not re-derive it blind.

## Context

The candidate proposed a central **Sync ledger** subscribing to the push transport that owns, per JMAP type, `{last-seen state token, debounce window, full-reload-vs-incremental-/changes}`, so each consumer (inbox/calendar/tasks/contacts) registers only a refetch callback. Measured against the tree, it splits into two separable claims and **neither earns a standalone plan now**:

- **There is exactly ONE debounce, not a duplicated pattern.** Only the inbox debounces (`routes/inbox/+page.svelte:83,886-893`, 300 ms). `CalendarApp` refreshes **synchronously** on every push (`CalendarApp.svelte:101-104`). `RemindersStore.onPush` full-reloads but has **zero production callers** (grep finds `.onPush(` only in `reminders.test.ts`). The "every consumer re-invents `setTimeout(…,300)`" premise is false — there are two `connect()` consumers and one debounce.
- **No client state token is tracked** (`client.ts` has no `sinceState`/`Changes` helper); every push is a full reload. The server `/changes` family **fully exists** (`Email/changes` reads `jmap_email_state` as `v_current`, `jmap_email.sql:292`, and raises `cannotCalculateChanges`, `:299-301`) but is **never called from the client** — a deliberate "full reload is simpler" choice, not an accidental gap. The pushed token **is** a valid `sinceState` cursor (same `mailboxes.jmap_email_state` column), so incremental is **feasible** — not **wanted**.
- **The push path is untested at every consumer** (all mock `connect` as `vi.fn()`) — there is no regression net for a behavior-moving refactor.

The only live architectural move the ledger would make — a **multi-listener push hub** on `websocket.ts` — is **already owned, sequenced, and revert-bounded** by Decision **D3** of `retired-docs:superpowers/plans/archive/2026-06-18-wire-task-contact-push-reactivity.md` (LOCKED). A standalone ledger would be a **second hub racing a locked one** on the same files, and its unique delta (centralizing the debounce) **reverses** that plan's deliberate *per-consumer* debounce decision (plan line 55).

## Decision

**Defer.** Do not build a sync-ledger now.

1. **Debounce-centralization fails the deletion test today** — one instance moves, it does not concentrate (*one adapter = a hypothetical seam*). It also contradicts the locked per-consumer-debounce decision. The two defects the candidate cites as justification (singleton callback-drop; calendar's missing debounce) are **exactly what the locked hub PR (D3) fixes** — they are already someone else's revert boundary, not the ledger's.
2. **Incremental `/changes` is a feature, not a consolidation** — nothing to delete, no caller, and today's capped full-reload is **always-correct**; incremental trades it for a drift-prone stateful cache (gap detection, `cannotCalculateChanges`→resync, reconnect token staleness) with **no measured pain** on record.

### Conditions for resurrection (so it isn't lost)

- **(A) Debounce-hoist / token ledger as a consolidation** — revisit **only after** the locked hub PR **and** the Task + Contact consumers land, creating genuinely **3–4** consumers each carrying their own debounce. Only then does the duplicated pattern exist and a thin ledger *concentrate* it (deletion test passes). Even then it must **supersede via an explicit amendment** to the locked plan, never silently contradict it; mirror `RemindersStore` (a `.svelte.ts` class with `$state`), not a legacy `writable`.
- **(B) Incremental `Email/changes` sync as a feature** — a separate downstream plan that **depends on** the hub. Preconditions: (1) concrete measured pain (payload size, flicker, scroll-jump) justifying cache-drift risk over the capped full-reload; (2) stays **pure cache-coordination under ADR-002** — apply the gateway-returned `created/updated/destroyed` ids; **never hand-diff client snapshots or re-derive filter/sort** (that re-implements server logic — the hard line); (3) owns the `cannotCalculateChanges`/reconnect-gap **full-resync fallback** (RFC 8620); (4) ships its own tests (the push path has no net today).

## Considered options

- **Build the ledger now (as proposed).** Rejected: two plans editing one seam (`websocket.ts` + inbox + calendar) with conflicting debounce placement; premature abstraction over a decision with one implemented branch and zero token-value consumers.
- **Centralize only the debounce now.** Rejected: deletion test fails at one instance; reverses a locked decision.
- **Adopt incremental `/changes` now.** Rejected: trades an always-correct baseline for cache drift with no measured win; ADR-002 boundary risk.

## Consequences

- No code change. The hub remains owned solely by `wire-task-contact-push-reactivity` (D3); full-reload-on-token stays the baseline.
- The two resurrection paths (A consolidation, B feature) are recorded with their preconditions and the ADR-002 guardrail, so the friction (real, but not actionable now) is not re-litigated from scratch.
- **Reversibility:** trivial — this defers work; nothing is built or deleted.
