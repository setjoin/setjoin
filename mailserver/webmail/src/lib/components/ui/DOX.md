<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# M1 UI Primitive Library — Agent Guide

> `mailserver/webmail/src/lib/components/ui/` — 28 Svelte 5 runes-mode primitives, plain-module helpers, and a barrel export. Built TDD (311 tests, 0 failures). This is the single source of truth for all setjoin UI building blocks.

---

## 1. Purpose

This directory is the M1 design-system primitive library. It provides the complete set of low-level UI components and pure utility modules used by every surface in the setjoin webmail (M2 shell through M8). Nothing above this layer re-implements these primitives — they are the shared contract between all higher-level surfaces.

---

## 2. Ownership

**This doc owns:**
- Every `.svelte` component and every `.ts` helper module in this directory.
- The barrel (`index.ts`) — the single import point for all consumers.
- All test files (`*.test.ts`, `*.svelte.test.ts`) for these primitives.

**Parent owns (do not duplicate here):**
- Svelte 5 runes mode conventions (see `mailserver/webmail/AGENTS.md`).
- `npm run check` / `npm run build` policy.
- JMAP types, stores, routes, and everything outside this directory.
- Project-wide token definitions (CSS custom properties live in `src/lib/theme/`).

---

## 3. Local Contracts

### Token-only styling
All color, spacing, radius, shadow, duration, and font references use CSS custom properties from the setjoin design token set (`--accent`, `--surface-card`, `--border-default`, `--focus-ring`, `--text-primary`, `--control-height`, etc.). No hardcoded hex values or pixel values for semantic colors. The sole exceptions are structural constants in `splitMath.ts` (`DIVIDER_PX = 1`, `KEYBOARD_STEP_PX = 16`) and the tag ×-hover tint (`rgba(20, 21, 29, 0.08)`). The modal-backdrop scrim uses the `--scrim` token (`colors.css`).

**Spacing is now token-governed too** (per `DESIGN.md` §4/§7). New raw-px `gap`/`padding`/`margin`/`height`/`width` in primitive `<style>` blocks is barred — use `--space-*`/`--row-height`/`--control-height*`. `spacing-lint.test.ts` is a **ratchet**: each primitive has a frozen raw-px-spacing baseline (the M1 library carries many intentional off-grid values); a count *above* baseline fails, and baselines may only be lowered as primitives migrate to tokens. 1px hairlines and `var(--token)` refs are allowed. **Small must-read text uses `--text-caption`** (AA ≥4.5:1), not `--text-tertiary` (below AA — decorative only); hint/error copy renders at `--text-sm`+.

### Svelte 5 runes throughout
Every `.svelte` file uses `$state`, `$derived`, `$effect`, `$props`, `$props.id()`. Event handlers use `onclick=` not `on:click`. No legacy syntax in any file.

### Focus-ring convention
Every interactive element uses `box-shadow: var(--focus-ring)` on `:focus-visible` with `outline: none`. The native outline is always suppressed. This applies to buttons, inputs, checkboxes (via sibling span), switches, radios, tabs, sidebar items, menu items, resizer, table sort buttons, and all pagination controls.

### Disabled-handler guard pattern
`Button` and `IconButton` extract `disabled` and `onclick` from `$props` and pass `onclick={disabled ? undefined : onclick}` to the element. This is required because jsdom fires synthetic `click` events on disabled buttons (the HTML spec says browsers must not fire click on disabled buttons, but jsdom does not enforce this). Every new interactive primitive must apply the same guard when it exposes a click handler on a native `<button>`.

`Checkbox` and `Switch` apply the same guard on `onchange` plus an `onclick` that calls `e.preventDefault()` when disabled, because `<input type="checkbox">` and `<input type="checkbox" role="switch">` do not suppress changes from label clicks when `disabled` is set dynamically in jsdom.

### Auto-generated IDs
Every primitive that needs a stable `id` for label association calls `$props.id()` to get a component-unique integer, then builds strings like `` `sj-input-${uid}` ``. Never use `Math.random()` or counters from module scope.

### Plain-module helpers
Logic that does not need the DOM lives in `.ts` modules beside the component: `avatarHash.ts`, `datetime.ts`, `pagination.ts`, `splitMath.ts`, `table.ts`, `tag.ts`. These are imported directly by the component and exported from the barrel so callers can also use them without importing the component.

### Barrel (`index.ts`)
`import { Button, Dialog, showToast } from '$lib/components/ui'` is the only approved import path. Do not import individual component files directly. When adding a primitive, export both the component and any public types/functions from `index.ts`.

### Key files

| File | Role |
|---|---|
| `index.ts` | Barrel — single import point for all 28 primitives and helpers |
| `types.ts` | Shared type vocabulary: `ButtonVariant`, `ButtonSize`, `IconButtonVariant`, `IconButtonSize`, `FieldSize`, `SelectOption`, `normalizeOptions()` |
| `tag.ts` | `TAG_COLORS` constant (8 hues), `TagColor` type, `splitTagPath()` |
| `avatarHash.ts` | `avatarHash()`, `avatarHue()`, `avatarInitials()` — cross-client stable algorithm |
| `datetime.ts` | `buildTimeSlots()`, `combineDateTime()`, `isFuture()`, `toDateStr()`, `toTimeSlot()` |
| `pagination.ts` | `pageCount()`, `formatRange()` |
| `splitMath.ts` | `resolveSplit()`, `paneLimits()`, `dragSize()`, `stepSize()`, `ratioFor()`, `clamp()`, constants |
| `table.ts` | `TableColumn`, `SortDir`, `nextSort()`, `ariaSort()` |
| `toasts.svelte.ts` | `toasts` reactive array, `showToast()`, `dismissToast()`, `pauseToast()`, `resumeToast()`, `clearToasts()` |

---

## 4. Features / Capabilities

### Buttons

- **Button** (`Button.svelte`) — action control. Props: `variant` (primary / secondary / ghost / danger), `size` (sm=26px / md=32px / lg=40px), `icon` (leading Snippet), `children` (label Snippet), `disabled`, `type`, `class`, plus all `HTMLButtonAttributes`. Variant `primary` uses `--accent` fill; `secondary` has border + card bg + shadow; `ghost` is transparent with hover; `danger` uses `--danger-solid`. CSS class: `.sj-btn`. Disabled-click guard applied.

- **IconButton** (`IconButton.svelte`) — square icon-only button for toolbars and row actions. Props: `label` (required — becomes `aria-label` and `title`), `variant` (ghost / outline), `size` (sm=26px / md=32px), `active` (indigo selected tint for toggled state). `outline` variant adds border + card background for standalone use. CSS class: `.sj-iconbtn`. Disabled-click guard applied.

### Forms

- **Input** (`Input.svelte`) — text field with label/hint/error stack. Props: `label`, `hint`, `error` (switches border to danger, sets `aria-invalid`), `size` (md / lg), `mono` (switches to `--font-mono` for hostnames, IPs, config values), `value` (bindable), plus all `HTMLInputAttributes` except `size` and `value`. Auto-generates `id` via `$props.id()`; wires `aria-describedby` to hint or error span. Uses explicit `oninput` handler rather than `bind:value` so `type` can flow through rest props; long machine identifiers in labels wrap within the field. CSS class: `.sj-input`.

- **Select** (`Select.svelte`) — styled native `<select>` with label. Props: `label`, `options` (array of strings or `{value,label}` objects, normalized via `normalizeOptions()`), `value` (bindable), `children` (fallback `<option>` elements). Custom SVG caret; `appearance: none`. CSS class: `.sj-select`.

- **Checkbox** (`Checkbox.svelte`) — 16px square checkbox with indeterminate support. Props: `checked` (bindable), `indeterminate` (dash for select-all rows; sets `inputEl.indeterminate` via `$effect`), `disabled`, `label`, `id`, `onchange`. Native input is visually hidden (`position:absolute; opacity:0; width:0; height:0`); visible box is a sibling `<span>` with SVG check or dash. Disabled guard on both `onclick` and `onchange`. Focus ring via `:focus-visible + .sj-check__box`.

- **Switch** (`Switch.svelte`) — hot-toggle for settings. The 32×18px track, 14px thumb, and 2px inset come from shared `--switch-*` geometry tokens; motion uses `duration-base`. Props: `checked` (bindable), `disabled`, `label`, `description` (secondary line under label), `id`, `onchange`. Role `switch` with `aria-checked`. Disabled guard on both `onclick` and `onchange`. Focus ring via `:focus-visible + .sj-switch__track`; bounded labels wrap instead of forcing horizontal overflow.

- **Radio** (`Radio.svelte`) — 16px radio button. Props: `checked`, `disabled`, `label`, `name`, `value`, `onchange(value: string)`. Native input hidden; visible circle with indigo fill + white inner dot when selected. Focus ring via `:focus-visible + .radio__circle`. Disabled guard on `onchange`.

- **Textarea** (`Textarea.svelte`) — resizable multi-line field with label/hint/error stack. Props: `value` (bindable), `label`, `hint`, `error`, `placeholder`, `rows` (default 3), `disabled`, `required`, `maxlength`, `oninput`. Min-height 64px; resize vertical; same border/focus/error styling as Input. CSS class: `.textarea`.

- **Tag** (`Tag.svelte` + `tag.ts`) — label chip with colored dot. Props: `label` (string; nested paths like `Finance/Invoices` rendered as breadcrumbs with `/` separator via `splitTagPath()`), `color` (one of 8 `TagColor` hues mapped to `--tag-{color}-bg/fg/dot`), `size` (md=22px / sm=18px), `dot` (show/hide the 7px dot), `onclick` (makes body a `<button>`), `onremove` (shows ×-button with `aria-label`). CSS class: `.tag`. `TAG_COLORS` constant: `['blue','teal','green','amber','orange','rose','purple','gray']`.

### Display & Navigation

- **Badge** (`Badge.svelte`) — status pill. Two modes: (1) semantic label — props `variant` (neutral / success / warning / danger / info / accent), `dot` (6px status dot), `label`; colors from token triples per variant; (2) count pill — prop `count` (number); renders in mono font on `--accent` background; values >99 display as `99+`. Height 20px, full-radius. CSS class: `.badge`.

- **Avatar** (`Avatar.svelte` + `avatarHash.ts`) — round avatar. Props: `name` (display name), `src` (photo URL), `size` (sm=24px / md=32px / lg=40px / xl=64px). Without `src`: shows 1–2-letter initials from `avatarInitials(name)` on a deterministic background hue from `avatarHue(name)`. Algorithm: Java-style 31× hash with `| 0` signed 32-bit overflow, modulo 8 hues. The hash algorithm is cross-client stable — do not change it. Font size is 38% of avatar diameter. CSS class: `.avatar`.

- **Card** (`Card.svelte`) — content container. Props: `title` (header text), `flush` (removes body padding), `actions` (Snippet for header right-side controls), `children` (required body Snippet). Renders header only when `title` or `actions` is provided. CSS class: `.card`.

- **Tabs** (`Tabs.svelte`) — tab strip. Exports `TabItem` interface (`{id, label, count?}`). Props: `items` (array of `TabItem`), `active` (id of active tab), `onChange(id)`. Active tab has indigo 2px bottom indicator overlapping the strip hairline. Count pill (mono, 11px) shown for any non-null count including 0. Role `tablist` / `tab`. Focus ring on `:focus-visible`. Height 36px.

- **SidebarItem** (`SidebarItem.svelte`) — 30px sidebar navigation row. Exports `TagHue` type. Props: `label`, `icon` (16px Snippet, option A), `dotColor` (8px hue dot, option B; wins over icon when both set), `count` (right-aligned mono unread count; hidden when 0 or null), `active` (indigo selected background + accent text), `depth` (nesting: left-padding = 8 + depth×16 px), `onclick`. `aria-current` set when active. CSS class: `.sbitem`.

- **Menu** (`Menu.svelte`) — accessible dropdown menu. Exports `MenuItem` interface (`{id, label, destructive?}`). Props: `items`, `onSelect(id)`, `label`, `align` (start / end — popover horizontal alignment), `children` (custom trigger Snippet). Full keyboard navigation: ArrowDown/ArrowUp move focus through items; Home/End jump to first/last; Escape closes and returns focus to trigger; Tab closes without refocus. Outside-click via `pointerdown` on document. Destructive items rendered in `--danger-fg`. WAI-ARIA: `aria-haspopup="menu"`, `aria-expanded`, `role="menu"`, `role="menuitem"`. CSS class: `.menu`.

- **Tooltip** (`Tooltip.svelte`) — text tooltip wrapping any trigger. Props: `text` (tooltip string), `children` (required Snippet — the wrapped trigger). Show with 500ms delay on mouseenter; immediate on focusin. Hides on mouseleave, focusout, Escape. Auto-places above the trigger (6px gap) or flips below when there is not enough room above. Wires `aria-describedby` to the tooltip via `$effect` on the trigger's first child. Timer always cleared on component destroy. CSS class: `.tooltip`. Z-index 60. Max-width 240px.

- **Resizer** (`Resizer.svelte`) — vertical drag handle. Props: `label` (accessible name), `valueNow/valueMin/valueMax` (ARIA separator values), `onStep(delta)` (ArrowLeft/Right ±16px), `onDragStart/onDrag(dx)/onDragEnd` (pointer lifecycle), `onReset` (double-click). WAI-ARIA `role="separator"` with `aria-orientation="vertical"`. `setPointerCapture` on pointer down (best-effort; jsdom raises on untrusted events). 6px hit area centered on 1px hairline. Highlights `--accent` on hover, drag, and focus. Touch-action none. Used exclusively by `SplitPane`.

- **SplitPane** (`SplitPane.svelte`) — two-pane layout with persisted ratio. Props: `storageKey` (localStorage key), `defaultRatio` (fallback + double-click reset target), `minA/minB` (minimum pane widths px), `maxA/maxB` (optional max widths px), `label` (resizer accessible name), `onCollapse` (fires once when total width < minA+minB), `a`/`b` (pane Snippets). Uses `ResizeObserver` (falls back to `resize` event). Persists ratio to localStorage after drag end, step, and reset. Pane B is kept mounted (hidden via `hidden` attribute) when collapsed — keep-alive for scroll/selection/form state. The `splitMath.ts` module contains all geometry (`resolveSplit`, `paneLimits`, `dragSize`, `stepSize`, `ratioFor`, `clamp`, `KEYBOARD_STEP_PX=16`, `DIVIDER_PX=1`).

### Feedback & Data Display

- **Dialog** (`Dialog.svelte`) — modal overlay. Props: `open`, `title` (required; wired to `aria-labelledby`), `wide` (max-width 640px instead of 440px), `onClose`, `children` (body Snippet), `footer` (Snippet; right-aligned, hairline separated). The shared stacked focus trap cycles Tab/Shift+Tab, contains focus, restores prior focus on close, and ensures only the topmost nested dialog handles Escape. Backdrop mousedown on the scrim (not dialog itself) calls `onClose`. Backdrop fade-in + dialog scale-in animations; `prefers-reduced-motion` disables them. `tabindex="-1"` on dialog div receives initial focus. The body wraps long identifiers; the close control expands to the 44px coarse-pointer floor without changing its desktop visual size. Z-index 1000. CSS class: `.sj-dialog`.

- **ConfirmDestructive** (`ConfirmDestructive.svelte`, Chat A4a Task 12) — typed-confirm dialog for irreversible actions, wrapping `Dialog`. Props: `open`, `title`, `message` (consequences paragraph — plain text, caller does its own i18n interpolation), `confirmWord` (the exact string that must be typed — a channel/resource name, or a literal word like `"DESTROY"`), `confirmLabel` (danger-button text), `busy`, `error`, `onConfirm`, `onCancel`. The confirm button stays `disabled` until the typed `Input` exactly matches `confirmWord`; the typed value resets on every `open` transition. Label text is `common.type_to_confirm` (`'Type {value} to confirm'`). Generalizes the remote-wipe type-to-confirm shape first built ad hoc in `admin/offline/DeviceApprovalQueue.svelte` — new destructive-confirm UI should use this primitive, not a sixth hand-rolled copy. Its own unit test lives here (`ConfirmDestructive.test.ts`); an additional in-context render lives in `routes/admin/(access)/chat-compliance/chat-compliance.test.ts` (the first consumer).

- **Toast** (`Toast.svelte` + `toasts.svelte.ts`) — bottom-left toast stack. `Toast.svelte` renders `toasts` array from the module store; consumers call `showToast()`. The store (`toasts.svelte.ts`) exports: `showToast(message, options)` → `ToastHandle`; `dismissToast(id)`; `pauseToast(id)`; `resumeToast(id)`; `clearToasts()`; `toasts` (reactive `$state` array). `ToastOptions`: `actionLabel`, async-capable `onAction`, `durationMs` (default 6000ms; `0` disables automatic dismissal even after hover/focus resumes), and `variant`. When `onAction` is provided, any existing actionable toast is replaced (single action slot). Hover **and keyboard focus** pause expiry. An async action pauses expiry, disables itself against duplicate activation, and dismisses only after success; rejection leaves the action available so the caller's announced error path is not replaced by fake success. Danger toasts use `role=alert`; other variants use `role=status`. Action and dismiss controls expand to the 44px coarse-pointer floor without changing desktop layout. Toast slides in from bottom; `prefers-reduced-motion` disables animation. Z-index 1100 (above Dialog). CSS class: `.sj-toast-stack` / `.sj-toast`.

- **Spinner** (`Spinner.svelte`) — indeterminate loading indicator. Props: `size` (16 / 20 / 28 — only these three values), `label` (aria-label, default `"Loading"`). CSS border-spin at 0.8s linear; `prefers-reduced-motion` switches to opacity pulse. Role `status`. CSS class: `.sj-spinner`.

- **Progress** (`Progress.svelte`) — determinate horizontal bar. Props: `value` (required), `max` (default 100), `label` (required aria-label). 4px height, full-radius, `--accent` fill. `aria-progressbar` with valuenow/min/max. Width animates on change via `duration-base`. CSS class: `.sj-progress`.

- **EmptyState** (`EmptyState.svelte`) — centered empty-list placeholder. Props: `title` (required message), `watermark` (show 35%-opacity brand logo mark), `action` (Snippet for a CTA button). CSS class: `.sj-empty`.

- **Pagination** (`Pagination.svelte` + `pagination.ts`) — row navigator. Props: `page` (1-based), `pageSize`, `total`, `pageSizeOptions` (default `[25,50,100]`), `onPageChange(page)`, `onPageSizeChange(size)`. Shows range label (`"1–50 of 1,283"` — en-dash, en-US comma grouping) via `formatRange()`. Prev/next `<button>` with SVG chevrons; disabled when at boundary. Rows-per-page `<select>`. `pageCount()` helper: `ceil(total/pageSize)`, min 1. CSS class: `.sj-pagination`.

- **DateTimePicker** (`DateTimePicker.svelte` + `datetime.ts`) — inline date+time picker popover panel. Props: `value` (optional seed `Date`), `confirmLabel` (default `"Confirm"`), `onConfirm(date: Date)`. Renders a native `<input type="date">` and a `<select>` of 48 half-hour slots (00:00–23:30) built by `buildTimeSlots()`. On confirm: `combineDateTime()` parses and validates the pair, then `isFuture()` checks it; shows inline error if invalid or past. Seeded once at construction from `value ?? new Date()`; no controlled re-sync after mount. Mono font for date/time inputs. CSS class: `.sj-dtp`.

- **Table** (`Table.svelte` + `table.ts`) — data table with caller-side sorting. Generic over `T extends Record<string, unknown>`. Props: `columns` (`TableColumn[]`), `rows` (`T[]`), `sortKey`, `sortDir` (asc/desc), `onSort(key, dir)`, `cell` (optional Snippet`<[T, TableColumn]>` for custom cell rendering; default renders `String(row[col.key])`), `footer` (Snippet, typically `<Pagination />`). Column definition: `{ key, label, sortable?, mono?, width? }`. Sort headers are `<button>` elements emitting `onSort`; the component never reorders rows. `nextSort()`: new column → asc; same column → flip direction. `ariaSort()`: returns `ascending/descending/none/undefined` for header `aria-sort`. Mono column renders `--font-mono` in cells. Horizontal scroll wrapper. CSS class: `.sj-table`.

### Controls

- **Slider** (`Slider.svelte`) — discrete-stop range slider over a native `<input type="range">` (min 0 / max `stops.length-1` / step 1), so arrow/Home/End/PageUp keyboard nav and the `slider` role come for free. Props: `label` (→ `aria-label`), `value` (bindable stop index), `stops` (string[] tick labels; `aria-valuetext` = `stops[value]`), `oninput(index)`, `tone` (`normal`/`danger` — flips `accent-color` to `--danger-solid` for an overflow / "won't fit" state, with a forced-colors thumb ring), `disabled` (inert: desaturated, not-allowed cursor), `describedById` (wires `aria-describedby` to a live estimate line). 44px touch target on coarse pointers. Built for the offline #1b Storage window picker. CSS class: `.sj-slider`.

### Types & Shared Utilities

- **`types.ts`** — shared vocabulary: `ButtonVariant` (`primary|secondary|ghost|danger`), `ButtonSize` (`sm|md|lg`), `IconButtonVariant` (`ghost|outline`), `IconButtonSize` (`sm|md`), `FieldSize` (`md|lg`), `SelectOption` (`{value,label}`), `normalizeOptions(options)` (coerces string[] to `SelectOption[]`).

- **`avatarHash.ts`** — `AVATAR_HUES` (8 CSS var references), `avatarHash(s)` (Java-style 31× hash, `| 0` signed overflow), `avatarHue(name)`, `avatarInitials(name)`. Algorithm is cross-client stable; do not change.

- **`datetime.ts`** — `TimeSlot` interface, `buildTimeSlots()` (48 half-hour slots), `combineDateTime(dateStr, timeStr)` (returns `Date | null`; validates calendar rollover), `isFuture(d, now?)`, `toDateStr(d)` (`"YYYY-MM-DD"`), `toTimeSlot(d)` (nearest half-hour at or before).

- **`pagination.ts`** — `pageCount(total, pageSize)`, `formatRange(page, pageSize, total)` (en-US locale, en-dash).

- **`splitMath.ts`** — `PaneConstraints`, `SplitInput`, `PaneLimits`, `SplitResult` interfaces; `KEYBOARD_STEP_PX=16`, `DIVIDER_PX=1`; `paneLimits()`, `resolveSplit()`, `stepSize()`, `dragSize()`, `ratioFor()`, `clamp()`.

- **`table.ts`** — `SortDir` type, `TableColumn` interface, `nextSort()`, `ariaSort()`.

- **`tag.ts`** — `TAG_COLORS` tuple (8 hues in picker order), `TagColor` type, `splitTagPath(label)`.

- **`toasts.svelte.ts`** — `ToastOptions`, `ToastItem`, `ToastHandle` interfaces; `toasts` reactive `$state` array; `showToast`, `dismissToast`, `pauseToast`, `resumeToast`, `clearToasts`.

---

## 5. Work Guidance

- **Token-only styling.** Never introduce hardcoded hex colors or semantic pixel values. If a new token is needed, define it in the theme layer first.
- **One primary per view.** `Button variant="primary"` — only one per visible view. Enforce in code review.
- **Size vocabulary.** `sm=26px`, `md=32px` (default), `lg=40px` (hero/login forms only). Do not invent other sizes.
- **Disabled-click guard required.** Any new interactive primitive with an `onclick` on a `<button>` must apply `onclick={disabled ? undefined : onclick}`. See Section 3.
- **Auto-IDs.** Use `$props.id()` for all label associations. Never use module-scope counters or `Math.random()`.
- **avatarHash is frozen.** The algorithm must produce identical output on web, desktop (Tauri/Rust), iOS (Swift), and Android (Kotlin). A change here requires simultaneous updates across all four clients.
- **splitMath is pure.** Keep geometry in `splitMath.ts` separate from component state. All functions are pure and must remain independently testable.
- **Barrel hygiene.** Export every new public symbol from `index.ts` in the appropriate section comment block.
- **No inline styles for semantic values.** `style="background: var(--tag-{color}-dot)"` is the only approved pattern for dynamic token references (required because CSS classes cannot be generated dynamically in Svelte's scoped style blocks).

---

## 6. Verification

```bash
# From mailserver/webmail/
npx vitest run src/lib/components/ui   # must be 311 passed, 0 failed
npm run check                          # must be 0 errors, 0 warnings
```

The tests cover: all 28 component files (render, variant permutations, keyboard interaction, ARIA attributes, disabled guards) and all plain-module helpers (avatarHash, datetime, pagination, splitMath, table, tag, toasts, types, barrel completeness). After adding any new primitive, the test count will increase — update this number here.

---

## 7. Child DOX Index

None.
