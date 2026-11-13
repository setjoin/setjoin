# ADR: ARCH-010 — Defer the unified app registry at N=4; `navConfig.ts` already owns the real nav seam, the dock dimension is unbuilt

**Status:** Accepted (as a deferral, with a trigger + one banked cleanup). **The dock-dimension premise is superseded (whole-pipeline review UX #19, 2026-07-16): `SideDock` was deleted, not kept as an unwired frame** — see the note at the end. The registry-deferral reasoning (§"Decision" points 1–2, the app-registry candidate itself) still holds; only the "dock stays an unwired frame" consequence changed.
**Date:** 2026-06-19
**Source:** Webmail architecture review (`/improve-codebase-architecture` over `mailserver/webmail/src/`) → candidate **app-registry** → adversarial validate/refute + `/grill-with-docs` 2026-06-19. The user confirmed `AppId` is **frozen at 4** (mail/calendar/contacts/tasks) for the client-unification program — no committed 5th app.

## Context

The candidate proposed one `AppRegistry` array owning rail/drawer/**dock** nav + `activeApp` derivation + the route guard + landing paths + the apps-grid tiles + the `AppId` type. Reading the code:

- **The nav half is already centralized and earns its keep.** `navConfig.ts:26-31` `RAIL_APPS` is consumed by `AppRail.svelte:35`, `GlobalDrawer.svelte:40`, `SideDock.svelte:47` — a real seam with 3 adapters; deleting it re-scatters id/label/icon/path. The highest-value de-dup is done.
- **The residual duplication is small, stable, and non-uniform** — ~4 maps (`activeApp` prefixes `+layout.svelte:34-43`; `appForPath` route guard `:71-74`; `session.ts` `APP_PATHS:26-31`; `apps/+page.svelte:31-37` tiles) ≈ 19 lines of config. Two of them (`activeApp`, apps-grid) fold in `settings` (always-on, no capability) and `admin` (permission-gated, carries `RAIL_ADMIN` sub-consoles) — **non-capability** entries a uniform `enabledApps`-shaped registry can't cleanly absorb; part of the complexity would *move* into per-entry kind flags, not disappear.
- **The dock dimension is fiction.** `+layout.svelte:223-232` renders `<SideDock>` with **no `children` snippet**, so `SideDock.svelte:86 {@render children?.()}` renders nothing; no app mounts into the dock (the PIM apps mount via their own routes). It is a parked M2 frame, reachable by no user action, with **zero** per-app dock components. *One adapter = a hypothetical seam; the dock has zero.* A `dock?`/`component` field would design an interface for an unbuilt feature.
- At N=4 with quarterly app cadence and no committed 5th app, the full registry would edit **6 source + 4 test files to remove fewer lines than it adds** — premature DRY. The pain is theoretical, not observed.
- **ADR-002 fit:** any future registry's `capability` field stays **UX-only**; real gating remains server-side (`effectiveCapabilities` from `/jmap/session`; 403 enforcement). The existing guard enforces only when `$jmapSession?.effectiveCapabilities` is present, never on the stub `FALLBACK_CAPS` (`session.ts:7-11`) — a future registry **must preserve that fallback-vs-authoritative split**.

## Decision

**Defer the full registry (not drop).** Record the trigger; bank the one independent cleanup the idea surfaced.

1. **Trigger to flip to BUILD** (either sufficient): a **committed** 5th capability app (e.g. notes/files) grows `AppId` past 4; **or** the dock gets its first real per-app component actually rendered into `SideDock`'s `children` slot (→ a real dock seam with ≥2 adapters). "We might add notes someday" is **not** the trigger; a decorative dock widget is **not** the trigger.
2. **The bounded slice to build when triggered** (written so it's ready, not built now): extend the **existing** `navConfig.ts` `NavApp` seam with a `prefix` field (keep `path`); have `activeApp` (`+layout.svelte:34-43`), `appForPath` (`:71-74`), and `session.ts` `APP_PATHS` read from it — removing 3 hand-synced path maps without inventing a dock interface. **Out even then:** the `dock?`/`component` field (until the dock has ≥2 adapters) and folding the apps-grid tiles. Keep `settings`/`admin` as explicitly-flagged **non-capability** entries; preserve the fallback-vs-authoritative caps split.
3. **Banked now (independent of the registry):** delete the dead `labelEn`/`labelZh` fields from `navConfig.ts` `NavApp`/`NavAdmin` (`:10-24`) and every `RAIL_APPS`/`RAIL_ADMIN` row — **all three consumers ignore them** (`AppRail.svelte:40-46`, `GlobalDrawer.svelte:45-47`, `SideDock.svelte:65` all call `t(\`app.${id}\`)`; keys exist `en.ts:460+`). Gate: confirm `admin.console.{mail,system,logs,auth}` keys exist before stripping admin labels (leave any unkeyed label in place); `npm run check` 0/0 + nav tests green (update any test pinning the dead fields to assert the `t()`-resolved label — the real contract).

## Considered options

- **Build the full `AppRegistry` now.** Rejected: edits more than it removes at N=4; the dock dimension has zero adapters; `AppId`-derived-from-registry risks an import cycle with `types/jmap.ts`.
- **Drop the idea entirely (including the cleanup).** Rejected: the nav de-dup that already exists is correct, and the dead-label cleanup is a safe independent win; dropping the record would let a future review re-derive the speculative registry blind.
- **Model `settings`/`admin` as capability apps to unify.** Rejected: they have different gating (always-on / permission-gated) and would leak admin into capability logic; keep them flagged non-capability.

## Consequences

- No registry built. `navConfig.ts` stays the nav seam; the 4 residual maps stay until a trigger fires.
- The dead-label cleanup is bankable independently (ready task above).
- A future `/improve-codebase-architecture` pass finds this record and does not re-propose the registry (especially the speculative dock dimension) until a trigger is met — should the dock ever come back, design its content producer FIRST (see the update below).
- **Reversibility:** trivial — defers a refactor; the optional cleanup is revert-safe.

## Update 2026-07-16 (whole-pipeline review UX #19) — the dock frame was deleted, not kept

This ADR's §Context already named the exact defect ("the dock dimension is
fiction… renders nothing… reachable by no user action") but classified it as
an inert, low-stakes "parked frame" and left it mounted. A UX review of the
live app found that framing understated the cost: because `SplitPane`'s
`minA=360`/`minB=320` are satisfied on any normal desktop viewport, the
"parked frame" was not merely unreachable — it rendered as a permanent
~40%-width **empty panel** (live app-switcher `<select>` in its header, going
nowhere) next to the primary app on every desktop load, for the entire life
of this ADR. That is a real, visible UX defect, not a dormant one.

No trigger in point 1 above ever fired (no 5th capability app, no dock
consumer ever built across the Drive/Chat/Meet/Admin programs shipped since
this ADR) — the deferral's own "revert-safe" framing applies in reverse:
`SideDock.svelte`, `SideDock.test.ts`, the outer `SplitPane` wrap around the
primary app, and the `dockOpen`/`dockApp`/`openDock`/`handleDockCollapse`
state in `+layout.svelte` were deleted (`mailserver/webmail/AGENTS.md`'s App
shell section). The nav-seam reasoning (`navConfig.ts`/`RAIL_APPS`) is
unaffected — `SideDock` was one of three consumers, not the seam itself; the
other two (`AppRail`, `GlobalDrawer`) still stand. Should a real split-view
second-app pane be wanted later, point 2's bounded slice is still the right
shape to extend from, but the content producer (what mounts in pane B, and
what UI opens it) must be designed and built FIRST — do not remount an empty
slot.
