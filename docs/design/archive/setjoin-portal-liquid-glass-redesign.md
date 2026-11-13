# SetJoin Web Portal — Liquid Glass Redesign (Design + Outcome)

Date: 2026-06-01
Status: Partial — code shipped (unverified-against-0/0 due to pre-existing debt); mockup not done.

> **Web is one surface of a cross-platform language.** The Liquid Glass system this redesign
> aligned the webmail to is defined for *all* SetJoin surfaces (web · desktop · mobile) in
> [`liquid-glass-design-language.md`](./liquid-glass-design-language.md). Read that for the
> CSS → SwiftUI → Compose token mapping; this document is the web execution record.
>
> **Caveat (post-restructure):** the "0 errors / 0 warnings" and "gateway builds OK" claims below
> predate the `ea098c6` repo restructure and were not re-verified here (`node_modules` is not
> installed in this checkout). File paths have been corrected to the current tree.

## Context / Problem

The webmail has a mature, canonical "Liquid Glass" design system in
`mailserver/webmail/src/lib/theme/tokens.css` (aurora wallpaper, glass surfaces,
OLED-black dark mode, per-app accents, macOS spring easing). But the portal
surfaces had drifted off it:

- ~50 component `<style>` blocks reference a **legacy "Prism" token vocabulary**
  (`--gray-900`, `--bg-card`, `--radius-pill`, `--font-size-*`, `--color-danger`,
  `--duration-*`, `--c-*`, …) that is **defined nowhere**. Those properties were
  silently falling back to browser defaults → surfaces rendered partially broken,
  not just off-brand.
- The `/apps` launcher used the stale vocabulary and showed only 2 apps.
- Brand name was inconsistent: `Mailserver` (server default + several pages),
  `Prism` (layout), `SetJoin` (layout fallback + mockups).
- The static mockup (`clients/previews/webmail-preview.html`) used its own GitHub-style
  palette with no aurora and no real glass.

## Decisions (from user)

| Question | Answer |
|---|---|
| Deliverable | Mockup **then** code |
| Brand | Hard-align everything to **SetJoin** (Chinese tagline 集合) |
| Scope | **Whole webmail** |
| Launcher apps | **Only available apps** (Mail, Calendar, Contacts, Tasks, Admin) — no "coming soon" tiles |

Later course-correction (mid-run): budget became the constraint (~half of a 5h
limit spent). Multi-agent workflow execution was the wrong default for a
budget-bound session; remaining work to be done **inline, no agents**.

## Approach

**Key insight that makes "whole webmail" affordable:** the divergence is almost
entirely a token-vocabulary mismatch against undefined names. So instead of
editing ~50 files, define a **token bridge** that aliases every legacy name to its
canonical equivalent. One file repairs *and* unifies the entire app onto Liquid
Glass at once; aliases point at canonical `var()`s so they inherit light/dark
automatically. New code should use canonical tokens directly; the bridge is
transitional so legacy names can be retired file-by-file later.

Then redesign only the genuine "portal-core" surfaces directly on canonical tokens.

## What shipped (on disk, verified clean in svelte-check)

- `mailserver/webmail/src/lib/theme/compat.css` — **new** legacy→canonical token
  bridge (surfaces, hairlines, grays→`--fg-*`, radii, font sizes, weights,
  spacing, shadows, motion, named/state colors, `--c-*` family, banner tokens).
  Imported from `global.css` after `tokens.css`.
- **SetJoin branding**: `app.html` title; `admin/system/+page.svelte` (state +
  fallback + placeholder); `login.test.ts` (expects "SetJoin"); server defaults
  in `mailserver/internal/jmap/handler.go` and `mailserver/internal/admin/admin_branding.go`
  (gateway builds OK).
- **Launcher** `routes/apps/+page.svelte` — glass tiles on aurora, available-apps-only
  with per-app accents (Mail/Calendar/Contacts/Tasks/Admin), `<Icon>` not emoji.
- **Login** `routes/+page.svelte` + **Setup** `routes/setup/+page.svelte` — glass
  card on aurora, SetJoin + 集合, SSO buttons; auth/MFA/wizard logic preserved.
- **Shell** `routes/+layout.svelte` — wired the dead app-launcher button to an
  accessible glass app-switcher popover (Escape/outside-click close).
- **Modal** `lib/components/Modal.svelte` — real `--glass-modal` treatment
  (was undefined `--bg-surface` + hardcoded radius). API preserved.

~622 lines across 5 redesigned files + the bridge + branding.

## What did NOT complete

- **`clients/previews/webmail-preview.html` mockup** — unchanged (402 lines, original GitHub
  palette). The mockup agent was killed mid-flight when the workflow was stopped;
  it never wrote. The "mockup then code" sequence delivered only the code.

## Verification

`cd mailserver/webmail && npm run check` → **12 errors, 8 warnings**, ALL
**pre-existing and unrelated** to this work (confirmed: every erroring file is
unmodified vs HEAD):

- Errors: `lib/stores/scheduling.svelte.ts` (a `RoomFilter` cast) and
  `AvailabilityGrid`/`RoomFinder`/`SchedulingAssistant` (invalid Lucide icon names
  not in `Icon.svelte`'s map: `door-open`, `map-pin`, lowercase `users`/`search`/
  `calendar`, etc.).
- Warnings: unused CSS selectors in `inbox`, `admin/migration`, `admin/system`.

The 5 redesigned files introduced **0 new errors / 0 new warnings**.

## Open follow-ups (cheap, optional, inline)

1. Regenerate `clients/previews/webmail-preview.html` as a faithful Liquid Glass mockup
   (one file, no agents) — tracked as S3 of the cross-platform design-language work
   (see [`liquid-glass-design-language.md`](./liquid-glass-design-language.md)).
2. Reach the project's 0/0 `npm run check` bar by fixing the pre-existing debt:
   add the missing icon names to `lib/components/Icon.svelte` (or correct casing),
   fix the one `scheduling.svelte.ts` cast, remove unused CSS selectors.
3. Retire legacy token names file-by-file, shrinking `compat.css` toward empty.
