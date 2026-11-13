# setjoin webmail — design contract (DESIGN.md)

This document ratifies the design decisions made across the M0–M9 redesign +
client-unification program as the **binding design contract** for everything
under `mailserver/webmail/`. It is the "why" behind the tokens; the tokens in
`src/lib/theme/` are the "what". When the two disagree, fix the code — this is
the authority.

Scope: the SvelteKit webmail SPA (user mail client, PIM, settings, admin
console) and the 28-primitive UI library. Owned by `mailserver/webmail/AGENTS.md`
(local contracts) and `src/lib/components/ui/AGENTS.md` (primitive contracts);
this file is the design rationale they reference.

---

## 1. Aesthetic — flat over glass

The product is **flat and border-first**. The prior "Liquid Glass" language
(backdrop-filter, aurora wallpaper, glass surfaces, press-scale transforms) is
**design history** and is permanently barred:

- No `backdrop-filter`, no `blur()`, no aurora/gradient wallpaper.
- No glass surface classes (`glass-pane`, `glass-toolbar`, `glass-popover`,
  `glass-modal`, `glass-dock` render flat).
- Shadows stay quiet — borders do the separating, not elevation. The shadow
  scale (`--shadow-xs … --shadow-lg`) is for menus/dialogs/popovers only.
- No press-scale (`transform: scale`) on interaction — colour-state only.

Enforced by `src/lib/theme/tokens.test.ts` + the M8 audit greps in
`mailserver/webmail/AGENTS.md` §6.

## 2. Colour — indigo-only accent

A **single** brand accent: indigo `#4A50D0` (`--indigo-600`, `--accent`). There
is no secondary accent. Status uses the semantic triples (success/warning/
danger/info — each `fg`/`bg`/`solid`); tags use the 8-hue palette
(`--tag-{hue}-{bg,fg,dot}`). Per-app launcher accents exist but are decorative
chrome, never interactive accent.

Dark mode is a real theme (`<html data-theme="dark">`, set pre-paint), not a
filter — every semantic token has an explicit dark value. **All 8 tag hues must
define `bg`/`fg`/`dot` in both themes** (a missing dark dot silently breaks
`Tag.svelte`; guarded by the tag-completeness test).

## 3. Contrast floor — AA, and the `--text-caption` rule

Text that **must be read** clears WCAG AA (≥4.5:1) on **both** the page
(`--surface-page`) and card (`--surface-card`) surfaces:

- `--text-primary`, `--text-secondary` — body + secondary copy (pass with room).
- **`--text-caption`** (`#696D7E` light / `#888D9E` dark) — the AA-safe channel
  for *small* must-read text: input hints/errors, form labels, captions,
  timestamps, stat labels, counts. Light = 4.79:1 page / 5.14:1 card; dark =
  5.53:1 page / 5.07:1 card.
- `--text-tertiary` (`--gray-500`) is **3.52:1 on page — below AA**. It is for
  genuinely decorative / large / non-essential glyphs only (carets, separators,
  watermarks). **Do not** put small must-read text on it; reach for
  `--text-caption` instead.
- Links keep a legible **visited** state: `--link` / `--link-visited`, both
  ≥4.5:1 on page+card (`a:visited` is wired globally in `base.css`).

Guarded by `tokens.test.ts` (caption + secondary + link-visited contrast
assertions; tertiary asserted *below* AA to document why caption exists).

## 4. Spacing — the 4px grid, token-only

All spacing derives from a **4px base grid** via `--space-1 … --space-16`
(`spacing.css`). Radii (`--radius-xs/sm/md/lg/full`), control heights
(`--control-height*`), and row height (`--row-height`, 36px → 30px compact) are
likewise tokens.

**The token-only contract now extends to SPACING, not just colour.** Component
`<style>` blocks must not hardcode raw-px `gap`/`padding`/`margin`/`height` —
use the spacing/layout tokens. (Borders/hairlines of `1px`, focus geometry, and
the documented exceptions below are allowed.)

This is enforced like the colour contract — see §7.

## 5. Typography — IBM Plex Sans + system-first CJK

- **IBM Plex Sans** for UI/display, **IBM Plex Mono** for ids/code/meta —
  self-hosted in `static/fonts/`, **no CDN**, all `font-display: swap`.
- IBM Plex Sans has no CJK coverage, so `--font-sans` lists the installed
  platform Chinese families first (`PingFang SC`, `Microsoft YaHei UI`,
  `Noto Sans CJK SC`, and their supported equivalents), then the distinct
  self-hosted `Setjoin Noto SC Fallback` family. This makes a normal managed
  desktop transfer zero bundled CJK font bytes without weakening Chinese as a
  required locale.
- The Noto fallback is generated from pinned, licensed source faces into
  physically separate `unicode-range` WOFF2 shards. A minimal/air-gapped host
  downloads only shards containing rendered glyphs; declaring ranges over a
  monolithic font is forbidden. Source/output hashes, glyph coverage, range
  overlap and CSS reachability are release-tested. No font CDN is allowed.
- Size scale is fixed (`--text-2xs … --text-display`). **Small-text floor:**
  must-read error/hint copy and form labels render at `--text-sm` (13px) or
  larger — `--text-xs`/`--text-2xs` (11–12px) are kept only for dense, glanceable
  metadata (timestamps, counts, caps labels).

## 6. Status convention — dot + colour + icon

Status is conveyed by **a 6–8px solid dot + colour + (where space allows) a
Lucide icon** — never colour alone (colour-blind safety). Lucide icons at
`strokeWidth={1.75}`. **No emoji** in product chrome. Sentence case for all UI
strings; verb-first buttons; 24h clock; no exclamation marks. Reversible actions
use **act-then-undo toasts**, not confirm dialogs; dialogs are reserved for
irreversible admin actions with concrete consequence copy.

## 7. Token-only contract + enforcement

Colour, spacing, radius, shadow, duration, and font references use CSS custom
properties. No hardcoded hex or semantic px in component `<style>` blocks.

**Documented inline-style / literal exceptions** (the only sanctioned ones):

1. `splitMath.ts` structural constants — `DIVIDER_PX = 1`, `KEYBOARD_STEP_PX = 16`.
2. The tag ×-hover tint — `rgba(20, 21, 29, 0.08)` — opacity tint with no token.
   (The modal-backdrop scrim now uses the `--scrim` token defined in `colors.css`.)
3. Dynamic token references that CSS classes can't express in Svelte scoped
   styles: `style="background: var(--tag-{color}-dot)"`,
   `style:padding-left={...depth...}` (computed nesting), and similar
   `var(--token)`-only inline styles. The rule is: inline `style` may reference
   `var(--token)` but must not embed a raw literal.
4. `1px` hairline borders and focus-ring geometry.

**Lints (regression guards):**

- **Colour:** `var(--token, #literal)` fallbacks are banned (a fallback means the
  token is missing and the surface is off-design) — grep guard in AGENTS.md §6;
  `tokens.test.ts` guards the theme-token set + the no-glass/no-blur invariants.
- **Spacing (NEW):** `spacing-lint.test.ts` scans the **28 UI primitives**
  (`src/lib/components/ui/*.svelte`) for bare raw-px `gap`/`padding`/`margin`/
  `height`/`min-height`/`width` numerics in `<style>` blocks and fails on new
  raw-px spacing, allowing the documented exceptions (`1px` hairlines, the
  backdrop overlay, structural constants). It is intentionally scoped to the
  primitives first (the design-system floor); widening it to all of `src/**`
  is the recorded follow-up TODO in that test. The primitives are the contract
  surface — they must be raw-px-free so every higher surface inherits clean
  spacing.

---

## 8. Where the tokens live

`src/lib/theme/` — `colors.css` (+ dark block), `typography.css`, `spacing.css`,
`fonts.css`, `base.css`, `global.css`. `global.css` is the single import entry
(via `src/app.css`). Touch targets: `@media (max-width: 767px)` and
`@media (pointer: coarse)` lift dense 30px rows to ≥44px on touch devices while
preserving desktop density.

## 9. Verification

```bash
cd mailserver/webmail
npm run check    # 0 errors / 0 warnings — gating
npm test         # vitest incl. tokens.test.ts + spacing-lint.test.ts
```
