# Simplify Deferred Items Cleanup — Design Spec

**Goal:** Resolve 9 code quality issues identified by the simplify code review across webmail (Svelte/TS), gateway (Go), SQL, and scripts — all confirmed as real by code inspection.

**Architecture:** Three independent streams with no cross-dependencies. Each stream can be implemented, tested, and committed separately. Total ~30 files touched.

---

## Stream A: Webmail Cleanup (4 items)

### A1 — formatBytes/fmtBytes dedup → `$lib/utils/display.ts`

**Problem:** 4 files define their own byte-formatting function with near-identical logic:
- `ComposeModal.svelte` — `formatBytes(b: number)`  
- `users/+page.svelte` — `fmtBytes(b: number): string`
- `mailboxes/+page.svelte` — `fmtBytes(b: number): string`  
- `storage/+page.svelte` — `fmtBytes(b: number): string` (also handles TB/PB)

**Fix:**
1. Add `formatBytes(bytes: number, maxUnit?: string): string` to `$lib/utils/display.ts`
2. The function covers B → PB range (matching storage page's extended range)
3. Replace all 4 local definitions with imports from `$lib/utils/display`
4. Keep the name `formatBytes` everywhere (rename `fmtBytes` call sites)

**Files:** Create 1 (`display.ts`), Modify 4 (ComposeModal, users, mailboxes, storage)

### A2 — Admin modal boilerplate → shared `Modal.svelte`

**Problem:** 5 admin pages inline `<div class="modal-overlay" role="button" tabindex="-1">` with copy-paste Escape/click dismissal logic. The shared `$lib/components/Modal.svelte` already provides modal-overlay, focus management, Escape handling, and backdrop-click-to-close — used by calendar, contacts, tasks, and CrudTable.

**Fix:**
1. Wrap each inline modal content in `<Modal onclose={closeHandler}>` from `$lib/components/Modal.svelte`
2. Delete the inline modal-overlay divs, role attributes, tabindex, and keydown handlers
3. The modal content and form fields inside stay unchanged — only the wrapper changes

**Files:** Modify 5 (users, departments, mailboxes, retention, quarantine admin pages)

### A3 — Calendar O(n²) event filtering → `$derived` event map

**Problem:** `getMonthGrid()`, `getWeekDays()`, `getEventsForDay()` each independently filter the full `$events` array per cell. On a month view with 200 events = ~50 full array sweeps per render.

**Fix:**
1. Add a `$derived` that builds `Map<dateString, CalendarEvent[]>` once per render
2. All three lookup functions use `eventMap.get(dayDate)` instead of filtering `$events`
3. The map key is the calendar-date string (YYYY-MM-DD) matching the cell's day

**Files:** Modify 1 (`calendar/+page.svelte`)

### A4 — Contacts blob upload dedup → `uploadBlob()`

**Problem:** `contacts/+page.svelte` reimplements SHA-256 + blob upload (18 lines) despite `$lib/jmap/client.ts` already exporting `uploadBlob(file)`.

**Fix:** Replace the 18-line inline implementation with `const { blobId } = await uploadBlob(file)`.

**Files:** Modify 1 (`contacts/+page.svelte`)

---

## Stream B: Gateway Go Cleanup (2 items)

### B1 — CalDAV/CardDAV WebDAV dedup

**Problem:** `caldav/webdav.go` and `carddav/webdav.go` each define identical:
- `writeMultistatus(w, *multistatus) error` — set XML content type, write 207, encode
- `buildPropstat(href, *propReq, builder func) *response` — iterate requested props, split OK/not-found

The shared `webdav` package already exists as a middle layer but the protocol packages maintain parallel type hierarchies.

**Fix:**
1. Define a `PropertyProvider` interface in `webdav` that each protocol's `propReq` satisfies:
   ```go
   type PropertyProvider interface {
       Properties() []PropertyDescriptor
   }
   type PropertyDescriptor struct {
       Name string
       Ptr  interface{}
   }
   ```
2. Move `buildPropstat` and `writeMultistatus` into `webdav` as exported functions
3. Each protocol package implements `PropertyProvider` on its `propReq` type and keeps its protocol-specific `setProp` (the type-switch that genuinely differs between CalDAV and CardDAV)
4. Re-export or thin-wrap in each protocol package to minimize call-site churn

**Files:** Modify 3 (`webdav/webdav.go`, `caldav/webdav.go`, `carddav/webdav.go`)

### B2 — context.Background() → lifecycle context

**Problem:** 25+ uses of `context.Background()` across 5 production files. Operations cannot be cancelled during graceful shutdown.

**Fix:**
1. **Backup engine** (`backup/engine.go`): Add `ctx` field to `Engine` struct, initialized from server lifecycle context passed to `NewEngine`
2. **Migration orchestrator** (`migration/orchestrator.go`): `jobCtx` already derives from `context.WithCancel(context.Background())` — change the base to a lifecycle context
3. **SMTP outbound** (`smtp/outbound.go`): TLS session recording uses `context.Background()` — pass the caller's context
4. **Handlers** (`jmap.go`, `admin_system.go`): These are request-triggered — pass `r.Context()` since the operations should cancel when the request times out

**Files:** Modify 5 (engine.go, orchestrator.go, outbound.go, jmap.go, admin_system.go)

---

## Stream C: Scripts + SQL Cleanup (3 items)

### C1 — test.sh govulncheck

**Problem:** `|| true` on govulncheck lines silently swallows vulnerability findings. `"All tests passed."` prints unconditionally.

**Fix:**
1. Remove `|| true` from both govulncheck lines
2. Wrap the final echo in a success check: capture exit codes and only print pass message if all pass

**Files:** Modify 1 (`scripts/test.sh`)

### C2 — SQL duplicate function definitions

**Problem:** 4 pairs of files where a later `CREATE OR REPLACE FUNCTION` silently overrides an earlier definition. If a developer fixes a bug in the first file, the fix is silently overwritten.

| First file (dead) | Second file (authoritative) | Function |
|-------------------|---------------------------|----------|
| `rule_engine.sql` | `rule_engine_or.sql` | `apply_rules` |
| `deliver.sql` | `deliver_group_vacation.sql` | `deliver` |
| `utils_tags.sql` | `030_message_tags.sql` | `tag_message` |
| `024_dlp.sql` | `047_dlp_consolidate.sql` | `dlp_check` |

**Fix:**
1. Remove the obsolete function definitions from the 4 first files
2. Add a one-line comment in each superseded file: `-- apply_rules is defined in rule_engine_or.sql`
3. This is purely a maintenance hazard fix — no functional change since the second file's version is what actually runs

**Files:** Modify 4 (`rule_engine.sql`, `deliver.sql`, `utils_tags.sql`, `024_dlp.sql`)

### C3 — Scripts ROOT boilerplate dedup

**Problem:** All 5 scripts duplicate the same 3-line preamble (`set -euo pipefail`, `ROOT=$(...)`, etc.)

**Fix:**
1. Create `scripts/_base.sh`:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   ROOT="$(cd "$(dirname "${BASH_SOURCE[1]}")/.." && pwd)"
   ```
2. Source it at the top of each script: `source "$(dirname "$0")/_base.sh"`
3. Remove the duplicate `set -euo pipefail` and `ROOT=` lines from each script

**Files:** Create 1 (`_base.sh`), Modify 5 (build.sh, dev.sh, e2e.sh, lint.sh, test.sh)

---

## Summary

| Stream | Items | Files | Effort |
|--------|-------|-------|--------|
| A — Webmail | 4 | ~12 | Medium |
| B — Gateway | 2 | ~8 | Medium |
| C — Scripts/SQL | 3 | ~10 | Small |
| **Total** | **9** | **~30** | **~1 day** |
