# ADR: ARCH-009 — No collection-store / CRUD factory for the PIM apps; the per-app list→detail→CRUD lifecycle is intrinsic divergence

**Status:** Accepted
**Date:** 2026-06-19
**Source:** Webmail architecture review (`/improve-codebase-architecture` over `mailserver/webmail/src/`) → candidate **collection-store** → adversarial validate/refute (with measurement) + `/grill-with-docs` 2026-06-19.

## Context

The candidate proposed extracting a "copy-pasted list→select→detail→CRUD lifecycle" from `CalendarApp.svelte` (1629), `ContactsApp.svelte` (1121), `TasksApp.svelte` (853), and `inbox/+page.svelte` (1180) into a shared **collection-store factory**, premised on ~70% shared lifecycle. **Measurement refutes the premise:**

- **Only a ~12-line modal triad is byte-identical** across the three PIM apps: `showModal` / `modalMode: 'create'|'edit'|'detail'` / `editing<X>` + `openDetailModal()` + `closeModal()` (`TasksApp.svelte:24-26,104-113`, `ContactsApp.svelte:67-69,255-264`, `CalendarApp.svelte:32-34,369-378`), differing even there only by the typed target.
- **Everything the candidate calls "the lifecycle" diverges completely.** `openCreate`/`openEdit` build domain-specific forms with **zero shared fields** (Tasks 7 fields; Contacts seeds `emails`/`phones` arrays from `$selectedAddressBookId`; Calendar takes `(date,hour)` with two branches + `recurrenceParts`/`resourceAttendees`). `save<X>` fits **no common signature** — Calendar is **two-phase** (`saveEvent`→`showScopePrompt`→`applyScope`→`updateOccurrence`, `CalendarApp.svelte:408-460`), Contacts does email/phone **array** validation, Tasks a simple validate. `refresh<X>` and delete diverge (Tasks optimistic per-id `Set` + undo toast; Contacts `AbortController` + GAL + debounce).
- **The named layer — the stores — has no duplication.** `{tasks,contacts,calendar,contactGroups}.ts` are already thin one-line JMAP passthroughs over `$lib/jmap/client`. A "collection **store** factory" points at the wrong layer.
- **inbox is not a fourth instance** — no modal triad, no form lifecycle; it is a reading-pane/thread surface.

A factory over the divergent bodies is a **shallow module** (interface ≈ implementation): it would *move* complexity into per-app callbacks, not concentrate it — failing the deletion test. The complexity already lives, irreducibly, in each app's form/validation/save.

## Decision

**Do not build a collection-store / CRUD factory.** Per-app `openCreate`/`openEdit`/validation/`save`/`refresh`/`delete` stay **per-app permanently** — the divergence is intrinsic (no shared form fields; calendar's two-phase scope save; contacts' array validation; tasks' undo-toast). The stores stay as thin JMAP wrappers.

The **only admissible residue** (hygiene-tier, optional, not scheduled): if the ~12-line modal triad is ever judged worth a shared helper, extract **view-state only** — a `createModalController<T>()` **rune helper** in `mailserver/webmail/src/lib/utils/` (NOT a store; Svelte-5 `$state` per CLAUDE.md) returning `{ showModal, mode, editing }` + `openDetail(x)`/`close()`. It is gated **after** `retired-docs:superpowers/plans/archive/2026-06-18-wire-task-contact-push-reactivity.md` lands, because that plan rewrites the same `onMount`/`onDestroy`/refresh hunks **and** introduces a genuinely-duplicated `subscribe→refresh→unsubscribe` consumer triad across the same three apps — a **better extraction target** (a behavior contract, error-prone to hand-repeat) than the view-only modal triad. At ~12 lines, local clarity plausibly beats DRY; this is severity-hygiene, not worth-doing-now.

## Considered options

- **Build the store/CRUD factory (as proposed).** Rejected: premise false on measurement; shallow module; moves divergence into a god-callback parameter list; collides with the locked push-reactivity plan's edit surface.
- **Extract a base list/detail *component*.** Rejected (the candidate itself conceded): ~30% UI divergence (recurrence/RSVP, directory/groups, kanban) makes a shared template fragile (too many slots/variants).
- **Extract the modal triad now as a store.** Rejected: a `writable` store would make modal state global/cross-instance (wrong — it is per-component view state); and it collides with the locked plan. If ever done: a `$state` rune helper in `utils/`, sequenced second.

## Consequences

- No code change. The PIM apps stay as they are; the stores stay thin.
- The real future DRY target (the push-consumer triad) is named and correctly sequenced behind the locked plan, so a later review extracts *that*, not the mislabeled "store factory."
- **Reversibility:** trivial — defers an optional hygiene extraction.
