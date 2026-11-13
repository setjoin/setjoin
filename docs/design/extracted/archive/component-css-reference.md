# Setjoin Design System — Component CSS & Props Reference (archived)

**Status: durable archive.** This document preserves, verbatim, the complete embedded CSS and
TypeScript props contracts of all 14 components from the design bundle at
`docs/design/setjoin-design-system/` before that bundle is deleted. Once the bundle is gone,
**this file is the pixel-parity source of truth** for the setjoin component library.

Extracted 2026-06-13 from:

- `docs/design/setjoin-design-system/components/` (14 components × `.jsx` + `.d.ts` + `.prompt.md`)
- `docs/design/setjoin-design-system/ui_kits/shared/SJIcon.jsx`
- `docs/design/setjoin-design-system/tokens/fonts.css`
- `docs/design/setjoin-design-system/assets/` (4 SVGs — copied as files, see [Brand assets](#brand-assets))

Companion archives in this directory:

- `admin-kit-and-guidelines-reference.md` — admin UI kit + guidelines (colors, type, spacing, radius, shadows)
- `mail-kit-reference.md` — mail UI kit

## Conventions shared by all components

- **CSS injection pattern**: every component carries its CSS as a JS template string and injects it
  once per page via an `ensure<Name>Css()` guard — a module-level boolean plus
  `document.createElement("style")` with `style.dataset.sj = "<component>"` appended to `<head>`.
  SSR-safe (`typeof document === "undefined"` check). When porting to Svelte, the same CSS goes in
  the component `<style>` block (class names unchanged).
- **Class namespace**: all classes are prefixed `sj-` (e.g. `.sj-btn`, `.sj-tag__dot`). BEM-ish:
  block `--modifier`, `__element`.
- **Tokens**: all CSS references `var(--…)` design tokens defined in the tokens archive
  (`admin-kit-and-guidelines-reference.md`); none of the values below are hard-coded except where shown.
- **Icons**: 16–18px Lucide, `stroke-width: 1.75` (see [SJIcon](#sjicon-shared-icon-wrapper)).
- All `className` props append to the computed class string; all components accept `style`
  passthrough (Button/IconButton/Input/Select spread `...rest` onto the underlying element).

---

## 1. Button (`components/buttons/Button.jsx`)

### CSS (verbatim)

```css
.sj-btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  font-family: var(--font-sans); font-weight: var(--weight-medium); white-space: nowrap;
  border-radius: var(--radius-sm); border: 1px solid transparent; cursor: pointer;
  transition: background var(--duration-fast) var(--ease-out), border-color var(--duration-fast) var(--ease-out), color var(--duration-fast) var(--ease-out);
  text-decoration: none; }
.sj-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.sj-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.sj-btn--md { height: var(--control-height); padding: 0 12px; font-size: var(--text-sm); }
.sj-btn--sm { height: var(--control-height-sm); padding: 0 8px; font-size: var(--text-xs); }
.sj-btn--lg { height: var(--control-height-lg); padding: 0 16px; font-size: var(--text-md); }
.sj-btn--primary { background: var(--accent); color: var(--text-inverse); }
.sj-btn--primary:hover:not(:disabled) { background: var(--accent-hover); }
.sj-btn--primary:active:not(:disabled) { background: var(--accent-active); }
.sj-btn--secondary { background: var(--surface-card); color: var(--text-primary); border-color: var(--border-default); box-shadow: var(--shadow-xs); }
.sj-btn--secondary:hover:not(:disabled) { background: var(--gray-50); border-color: var(--border-strong); }
.sj-btn--secondary:active:not(:disabled) { background: var(--gray-100); }
.sj-btn--ghost { background: transparent; color: var(--text-secondary); }
.sj-btn--ghost:hover:not(:disabled) { background: var(--surface-hover); color: var(--text-primary); }
.sj-btn--ghost:active:not(:disabled) { background: var(--gray-200); }
.sj-btn--danger { background: var(--danger-solid); color: var(--text-inverse); }
.sj-btn--danger:hover:not(:disabled) { background: var(--danger-fg); }
.sj-btn__icon { display: inline-flex; flex: none; }
```

### Props contract (`Button.d.ts`, verbatim)

```ts
/**
 * Primary action control for setjoin surfaces.
 * @startingPoint section="Components" subtitle="Buttons — primary, secondary, ghost, danger" viewport="700x220"
 */
export interface ButtonProps {
  /** Visual style. Default "primary". One primary per view. */
  variant?: "primary" | "secondary" | "ghost" | "danger";
  /** Control height: sm=26, md=32 (default), lg=40 (hero forms only). */
  size?: "sm" | "md" | "lg";
  /** Optional leading icon (16px Lucide, stroke-width 1.75). */
  icon?: React.ReactNode;
  disabled?: boolean;
  children?: React.ReactNode;
  onClick?: (e: React.MouseEvent) => void;
}
export declare function Button(props: ButtonProps): JSX.Element;
```

### Behavior (from `Button.prompt.md`)

- Setjoin's action control — solid indigo primary, bordered secondary, quiet ghost, red danger; **one primary per view**.
- `size`: sm 26px / md 32px (default) / lg 40px — **lg only on login & hero forms**.
- `icon` takes a 16px Lucide ReactNode and renders before the label (wrapped in `<span class="sj-btn__icon">`).
- Labels are sentence case, verb-first ("Start migration", not "Migration").
- DOM: `<button class="sj-btn sj-btn--{variant} sj-btn--{size}">[icon span?]{children}</button>`; `...rest` spread onto `<button>`.

---

## 2. IconButton (`components/buttons/IconButton.jsx`)

### CSS (verbatim)

```css
.sj-iconbtn { display: inline-flex; align-items: center; justify-content: center; flex: none;
  border-radius: var(--radius-sm); border: 1px solid transparent; cursor: pointer;
  background: transparent; color: var(--text-secondary);
  transition: background var(--duration-fast) var(--ease-out), color var(--duration-fast) var(--ease-out); }
.sj-iconbtn:hover:not(:disabled) { background: var(--surface-hover); color: var(--text-primary); }
.sj-iconbtn:active:not(:disabled) { background: var(--gray-200); }
.sj-iconbtn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.sj-iconbtn:disabled { opacity: 0.5; cursor: not-allowed; }
.sj-iconbtn--md { width: var(--control-height); height: var(--control-height); }
.sj-iconbtn--sm { width: var(--control-height-sm); height: var(--control-height-sm); }
.sj-iconbtn--outline { background: var(--surface-card); border-color: var(--border-default); box-shadow: var(--shadow-xs); }
.sj-iconbtn--outline:hover:not(:disabled) { background: var(--gray-50); border-color: var(--border-strong); }
.sj-iconbtn--active { background: var(--surface-selected); color: var(--text-accent); }
.sj-iconbtn--active:hover:not(:disabled) { background: var(--accent-subtle-hover); color: var(--text-accent); }
```

### Props contract (`IconButton.d.ts`, verbatim)

```ts
/** Square icon-only button for toolbars, list-row actions, and topbars. */
export interface IconButtonProps {
  /** Required accessible name; also shown as tooltip via title. */
  label: string;
  /** ghost (default) for toolbars; outline for standalone placement. */
  variant?: "ghost" | "outline";
  /** sm=26 for dense list rows, md=32 (default). */
  size?: "sm" | "md";
  /** Pressed/toggled state — indigo tint. */
  active?: boolean;
  disabled?: boolean;
  /** The icon itself: 16–18px Lucide, stroke-width 1.75. */
  children: React.ReactNode;
  onClick?: (e: React.MouseEvent) => void;
}
export declare function IconButton(props: IconButtonProps): JSX.Element;
```

### Behavior (from `IconButton.prompt.md`)

- Square icon-only control for toolbars and row hover-actions; **always pass `label`** (rendered as both `aria-label` and `title` tooltip).
- `variant="outline"` adds border + card background for standalone use.
- `active` shows the indigo selected tint (toggled tools, current filter).
- Class composition: `sj-iconbtn sj-iconbtn--{size}` + ` sj-iconbtn--outline` when `variant === "outline"` + ` sj-iconbtn--active` when `active`.

---

## 3. Input (`components/forms/Input.jsx`)

### CSS (verbatim)

```css
.sj-field { display: flex; flex-direction: column; gap: 5px; font-family: var(--font-sans); }
.sj-field__label { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); }
.sj-field__hint { font-size: var(--text-xs); color: var(--text-tertiary); }
.sj-field__error { font-size: var(--text-xs); color: var(--danger-fg); }
.sj-input { height: var(--control-height); padding: 0 10px; font-family: var(--font-sans);
  font-size: var(--text-sm); color: var(--text-primary); background: var(--surface-card);
  border: 1px solid var(--border-default); border-radius: var(--radius-sm); width: 100%;
  transition: border-color var(--duration-fast) var(--ease-out), box-shadow var(--duration-fast) var(--ease-out); }
.sj-input::placeholder { color: var(--text-disabled); }
.sj-input:hover:not(:disabled):not(:focus) { border-color: var(--border-strong); }
.sj-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--indigo-100); }
.sj-input:disabled { background: var(--surface-sunken); color: var(--text-disabled); cursor: not-allowed; }
.sj-input--error { border-color: var(--danger-solid); }
.sj-input--error:focus { border-color: var(--danger-solid); box-shadow: 0 0 0 3px var(--danger-bg); }
.sj-input--lg { height: var(--control-height-lg); font-size: var(--text-md); padding: 0 12px; }
.sj-input--mono { font-family: var(--font-mono); }
```

### Props contract (`Input.d.ts`, verbatim)

```ts
/** Single-line text field with optional label, hint, and error. */
export interface InputProps {
  label?: string;
  /** Helper text below the field; replaced by error when set. */
  hint?: string;
  /** Error message; also switches border to danger. */
  error?: string;
  /** md=32 (default), lg=40 for login/hero forms. */
  size?: "md" | "lg";
  /** Mono rendering for hosts, IPs, config values. */
  mono?: boolean;
  placeholder?: string;
  value?: string;
  type?: string;
  disabled?: boolean;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
}
export declare function Input(props: InputProps): JSX.Element;
```

### Behavior (from `Input.prompt.md`)

- Standard setjoin text field — quiet border, indigo focus ring, label/hint/error stack.
- `mono` for hostnames, IPs, ports, config values.
- `size="lg"` only on login and other hero forms.
- Rendering rules: with no `label`/`hint`/`error`, renders the bare `<input class="sj-input …">`
  (style applied directly). Otherwise wraps in `<label class="sj-field">` with label span first,
  input, then **error replaces hint** when both are set.

---

## 4. Select (`components/forms/Select.jsx`)

### CSS (verbatim)

```css
.sj-select-wrap { position: relative; display: flex; flex-direction: column; gap: 5px; font-family: var(--font-sans); }
.sj-select-wrap__label { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); }
.sj-select { appearance: none; height: var(--control-height); padding: 0 28px 0 10px;
  font-family: var(--font-sans); font-size: var(--text-sm); color: var(--text-primary);
  background: var(--surface-card); border: 1px solid var(--border-default); border-radius: var(--radius-sm);
  width: 100%; cursor: pointer;
  transition: border-color var(--duration-fast) var(--ease-out), box-shadow var(--duration-fast) var(--ease-out); }
.sj-select:hover:not(:disabled):not(:focus) { border-color: var(--border-strong); }
.sj-select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--indigo-100); }
.sj-select:disabled { background: var(--surface-sunken); color: var(--text-disabled); cursor: not-allowed; }
.sj-select-caret { position: absolute; right: 9px; bottom: 9px; pointer-events: none; color: var(--text-tertiary); }
```

### Props contract (`Select.d.ts`, verbatim)

```ts
/** Native select with setjoin styling and custom caret. */
export interface SelectProps {
  label?: string;
  /** Options as strings or {value,label}; alternatively pass <option> children. */
  options?: Array<string | { value: string; label: string }>;
  value?: string;
  disabled?: boolean;
  onChange?: (e: React.ChangeEvent<HTMLSelectElement>) => void;
  children?: React.ReactNode;
}
export declare function Select(props: SelectProps): JSX.Element;
```

### Behavior (from `Select.prompt.md`)

- Styled native dropdown — **same field metrics as Input** (32px, radius-sm, indigo focus).
- `options` accepts plain strings (value = label) or `{value, label}` objects; if `options` is
  empty, `children` (`<option>` nodes) are rendered instead.
- Custom caret is an absolutely positioned inline SVG (chevron-down) at right 9px / bottom 9px,
  `pointer-events: none`:

  ```html
  <svg class="sj-select-caret" width="14" height="14" viewBox="0 0 24 24" fill="none"
       stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"></path></svg>
  ```

---

## 5. Checkbox (`components/forms/Checkbox.jsx`)

### CSS (verbatim)

```css
.sj-check { display: inline-flex; align-items: center; gap: 8px; cursor: pointer;
  font-family: var(--font-sans); font-size: var(--text-sm); color: var(--text-primary); user-select: none; }
.sj-check--disabled { opacity: 0.5; cursor: not-allowed; }
.sj-check__box { width: 16px; height: 16px; flex: none; border-radius: var(--radius-xs);
  border: 1.5px solid var(--border-strong); background: var(--surface-card);
  display: inline-flex; align-items: center; justify-content: center; color: var(--text-inverse);
  transition: background var(--duration-fast) var(--ease-out), border-color var(--duration-fast) var(--ease-out); }
.sj-check input { position: absolute; opacity: 0; width: 0; height: 0; }
.sj-check input:focus-visible + .sj-check__box { box-shadow: var(--focus-ring); }
.sj-check--on .sj-check__box { background: var(--accent); border-color: var(--accent); }
.sj-check:hover:not(.sj-check--disabled):not(.sj-check--on) .sj-check__box { border-color: var(--gray-500); }
```

### Props contract (`Checkbox.d.ts`, verbatim)

```ts
/** 16px checkbox with optional label; supports indeterminate for select-all. */
export interface CheckboxProps {
  checked?: boolean;
  /** Dash state for partial selections (e.g. mail list select-all). */
  indeterminate?: boolean;
  disabled?: boolean;
  label?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
}
export declare function Checkbox(props: CheckboxProps): JSX.Element;
```

### Behavior (from `Checkbox.prompt.md`)

- 16px, radius-xs, indigo when checked; indeterminate dash for select-all rows.
- The `sj-check--on` class applies when `checked || indeterminate`.
- Visually hidden native `<input type="checkbox">` drives state + focus; the box is a styled span.
- Glyphs are inline 10×10 SVGs (`stroke-width 3.5`):
  - indeterminate dash: `<path d="M5 12h14">`
  - checkmark: `<path d="M20 6 9 17l-5-5">`
  - unchecked: no glyph.

---

## 6. Switch (`components/forms/Switch.jsx`)

### CSS (verbatim)

```css
.sj-switch { display: inline-flex; align-items: center; gap: 8px; cursor: pointer;
  font-family: var(--font-sans); font-size: var(--text-sm); color: var(--text-primary); user-select: none; }
.sj-switch--disabled { opacity: 0.5; cursor: not-allowed; }
.sj-switch input { position: absolute; opacity: 0; width: 0; height: 0; }
.sj-switch__track { width: 32px; height: 18px; flex: none; border-radius: var(--radius-full);
  background: var(--gray-300); position: relative;
  transition: background var(--duration-base) var(--ease-out); }
.sj-switch__thumb { position: absolute; top: 2px; left: 2px; width: 14px; height: 14px;
  border-radius: var(--radius-full); background: var(--gray-0); box-shadow: var(--shadow-xs);
  transition: transform var(--duration-base) var(--ease-out); }
.sj-switch--on .sj-switch__track { background: var(--accent); }
.sj-switch--on .sj-switch__thumb { transform: translateX(14px); }
.sj-switch input:focus-visible + .sj-switch__track { box-shadow: var(--focus-ring); }
.sj-switch__desc { color: var(--text-tertiary); font-size: var(--text-xs); }
```

### Props contract (`Switch.d.ts`, verbatim)

```ts
/** Toggle switch — the control for runtime feature flags and settings. */
export interface SwitchProps {
  checked?: boolean;
  disabled?: boolean;
  label?: string;
  /** Secondary line under the label (e.g. resource impact). */
  description?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
}
export declare function Switch(props: SwitchProps): JSX.Element;
```

### Behavior (from `Switch.prompt.md`)

- Setjoin's hot-toggle control — feature flags reload in <1ms, so **switches apply instantly; no
  Save button next to them**.
- Hidden native checkbox carries `role="switch"`; track 32×18, thumb 14px translating 14px.
- Label + optional `description` stack in a column to the right of the track (gap 1px).

---

## 7. Tag (`components/display/Tag.jsx`)

### CSS (verbatim)

```css
.sj-tag { display: inline-flex; align-items: center; gap: 6px; height: 22px; padding: 0 8px;
  border-radius: var(--radius-sm); font-family: var(--font-sans); font-size: var(--text-xs);
  font-weight: var(--weight-medium); white-space: nowrap; border: none; }
.sj-tag--sm { height: 18px; padding: 0 6px; font-size: var(--text-2xs); gap: 5px; }
.sj-tag__dot { width: 7px; height: 7px; border-radius: var(--radius-full); flex: none; }
.sj-tag--sm .sj-tag__dot { width: 6px; height: 6px; }
.sj-tag__x { display: inline-flex; align-items: center; justify-content: center; width: 14px; height: 14px;
  margin-right: -3px; border: none; background: transparent; color: inherit; opacity: 0.55;
  cursor: pointer; border-radius: var(--radius-xs); padding: 0; }
.sj-tag__x:hover { opacity: 1; background: rgba(20, 21, 29, 0.08); }
.sj-tag--clickable { cursor: pointer; }
.sj-tag--clickable:hover { filter: brightness(0.96); }
```

### Props contract (`Tag.d.ts`, verbatim)

```ts
/**
 * Mail tag chip — the core organizational primitive of setjoin Mail.
 * @startingPoint section="Components" subtitle="Tag chips — 8 hues, dot, removable" viewport="700x170"
 */
export interface TagProps {
  /** One of the 8 system tag hues. */
  color?: "blue" | "teal" | "green" | "amber" | "orange" | "rose" | "purple" | "gray";
  /** md=22px (default), sm=18px for dense mail rows. */
  size?: "sm" | "md";
  /** Show the hue dot (default true). */
  dot?: boolean;
  /** When set, renders a remove ×. */
  onRemove?: (e: React.MouseEvent) => void;
  /** When set, the whole chip is clickable (filter by tag). */
  onClick?: (e: React.MouseEvent) => void;
  children: React.ReactNode;
}
export declare function Tag(props: TagProps): JSX.Element;
```

### TAG_COLORS export (verbatim JS)

```js
export const TAG_COLORS = ["blue", "teal", "green", "amber", "orange", "rose", "purple", "gray"];
```

### Behavior (from `Tag.prompt.md` + JSX)

- Setjoin's mail label chip — subtle tinted background, strong foreground, hue dot. Tags are
  systematic, never loud: **sm size in list rows, md in the reading pane and pickers**.
- Nested tags render the path in the chip: `<Tag color="blue">Finance/Invoices</Tag>`.
- `TAG_COLORS` export lists the 8 hues for pickers. **Don't invent hues** — assign from the
  8-color cycle.
- Colors come from inline styles built off the `color` prop (token triplet per hue):
  `background: var(--tag-{color}-bg)`, `color: var(--tag-{color}-fg)`,
  dot `background: var(--tag-{color}-dot)`. Default color: `gray`.
- Renders as `<button>` when `onClick` is set (adds `sj-tag--clickable`), otherwise `<span>`.
- `onRemove` renders the × button (`aria-label="Remove tag"`), which calls `e.stopPropagation()`
  before `onRemove(e)`. × glyph SVG: 9×9, `stroke-width 3`, `<path d="M18 6 6 18M6 6l12 12">`.

---

## 8. Badge (`components/display/Badge.jsx`)

### CSS (verbatim)

```css
.sj-badge { display: inline-flex; align-items: center; gap: 5px; height: 20px; padding: 0 7px;
  border-radius: var(--radius-full); font-family: var(--font-sans); font-size: var(--text-2xs);
  font-weight: var(--weight-semibold); letter-spacing: 0.02em; white-space: nowrap; }
.sj-badge__dot { width: 6px; height: 6px; border-radius: var(--radius-full); flex: none; }
.sj-badge--count { background: var(--accent); color: var(--text-inverse); min-width: 18px;
  justify-content: center; padding: 0 5px; font-family: var(--font-mono); }
```

### Props contract (`Badge.d.ts`, verbatim)

```ts
/** Status badge (pill) for states like Active, Locked, Queued; or a count badge. */
export interface BadgeProps {
  variant?: "neutral" | "success" | "warning" | "danger" | "info" | "accent";
  /** Leading status dot. */
  dot?: boolean;
  /** Render as solid indigo unread-count pill (mono digits). */
  count?: boolean;
  children: React.ReactNode;
}
export declare function Badge(props: BadgeProps): JSX.Element;
```

### Variant color map (verbatim JS — applied as inline styles)

```js
const VARIANTS = {
  neutral: { bg: "var(--gray-100)", fg: "var(--gray-600)", dot: "var(--gray-400)" },
  success: { bg: "var(--success-bg)", fg: "var(--success-fg)", dot: "var(--success-solid)" },
  warning: { bg: "var(--warning-bg)", fg: "var(--warning-fg)", dot: "var(--warning-solid)" },
  danger: { bg: "var(--danger-bg)", fg: "var(--danger-fg)", dot: "var(--danger-solid)" },
  info: { bg: "var(--info-bg)", fg: "var(--info-fg)", dot: "var(--info-solid)" },
  accent: { bg: "var(--accent-subtle)", fg: "var(--accent-fg-on-subtle)", dot: "var(--accent)" },
};
```

### Behavior (from `Badge.prompt.md` + JSX)

- The status pill — semantic variants for entity states; `count` mode for unread counters.
- **Tags vs badges: Tag = user organization (mail labels). Badge = system state. Don't mix.**
- `count` short-circuits: renders `sj-badge sj-badge--count` (solid indigo, mono digits) and
  ignores `variant`/`dot`.
- Unknown variant falls back to `neutral`. Variant colors are inline styles (`background`/`color`
  from the map above; dot span gets `background: dot`).

---

## 9. Avatar (`components/display/Avatar.jsx`)

### CSS (verbatim)

```css
.sj-avatar { display: inline-flex; align-items: center; justify-content: center; flex: none;
  border-radius: var(--radius-full); font-family: var(--font-sans); font-weight: var(--weight-semibold);
  color: var(--text-inverse); overflow: hidden; user-select: none; }
.sj-avatar img { width: 100%; height: 100%; object-fit: cover; }
```

### Props contract (`Avatar.d.ts`, verbatim)

```ts
/** Circular avatar — initials on a name-hashed hue, or an image. */
export interface AvatarProps {
  /** Full name; drives initials and the deterministic background hue. */
  name: string;
  /** Optional image URL; replaces initials. */
  src?: string;
  /** sm=24 (mail rows), md=32 (default), lg=40, xl=64 (profile). */
  size?: "sm" | "md" | "lg" | "xl";
}
export declare function Avatar(props: AvatarProps): JSX.Element;
```

### Hue palette, sizes, initials & hash algorithm (verbatim JS)

This algorithm is load-bearing: **the same name must produce the same hue on every surface and
every platform**. Any port (Svelte, Swift, Kotlin, Rust) must replicate the 31-multiplier
`charCodeAt` hash with 32-bit integer overflow (`| 0`) and `Math.abs`, modulo 8, exactly.

```js
const AVATAR_HUES = [
  "var(--tag-blue-dot)", "var(--tag-teal-dot)", "var(--tag-green-dot)", "var(--tag-amber-dot)",
  "var(--tag-orange-dot)", "var(--tag-rose-dot)", "var(--tag-purple-dot)", "var(--indigo-500)",
];

const SIZES = { sm: 24, md: 32, lg: 40, xl: 64 };

function initials(name = "") {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function hash(s = "") {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}
```

Hue selection and inline sizing (verbatim from the component body):

```js
const px = SIZES[size] || SIZES.md;
const bg = AVATAR_HUES[hash(name) % AVATAR_HUES.length];
// inline style:
// { width: px, height: px, fontSize: Math.round(px * 0.38),
//   background: src ? "var(--gray-200)" : bg, ...style }
```

### Behavior (from `Avatar.prompt.md`)

- Circle with initials on a hue deterministically hashed from the name (**same person, same color
  everywhere**).
- `src` replaces initials with an `<img>` (object-fit cover); background falls back to
  `var(--gray-200)` behind the image.
- Initials: single word → first two letters uppercased; multiple words → first letter of first +
  first letter of last word; empty name → `"?"`.
- `title={name}` set on the wrapper span. Font size = `round(px × 0.38)`.

---

## 10. Card (`components/display/Card.jsx`)

### CSS (verbatim)

```css
.sj-card { background: var(--surface-card); border: 1px solid var(--border-default);
  border-radius: var(--radius-md); box-shadow: var(--shadow-xs); font-family: var(--font-sans); }
.sj-card__header { display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 12px 16px; border-bottom: 1px solid var(--border-subtle); }
.sj-card__title { font-size: var(--text-md); font-weight: var(--weight-semibold); color: var(--text-primary); }
.sj-card__body { padding: 16px; }
.sj-card--flush .sj-card__body { padding: 0; }
```

### Props contract (`Card.d.ts`, verbatim)

```ts
/** Surface container — 1px border, radius-md, shadow-xs. The standard panel. */
export interface CardProps {
  /** Optional header title; header renders only when title or actions set. */
  title?: string;
  /** Right-aligned header actions (buttons, badges). */
  actions?: React.ReactNode;
  /** Remove body padding (for tables/lists that bleed to edges). */
  flush?: boolean;
  children: React.ReactNode;
}
export declare function Card(props: CardProps): JSX.Element;
```

### Behavior (from `Card.prompt.md`)

- The standard setjoin panel: white, 1px gray-200 border, 6px radius, whisper shadow. **Borders
  carry the elevation, not shadows.**
- Header renders only when `title` or `actions` is set; `actions` sit right-aligned in a flex span
  with 8px gap.
- `flush` removes body padding for tables/lists that bleed to the card edges.

---

## 11. Tabs (`components/navigation/Tabs.jsx`)

### CSS (verbatim)

```css
.sj-tabs { display: flex; gap: 2px; border-bottom: 1px solid var(--border-default);
  font-family: var(--font-sans); }
.sj-tab { position: relative; height: 36px; padding: 0 12px; display: inline-flex; align-items: center;
  gap: 6px; background: transparent; border: none; cursor: pointer; font-family: inherit;
  font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-secondary);
  border-radius: var(--radius-sm) var(--radius-sm) 0 0;
  transition: color var(--duration-fast) var(--ease-out), background var(--duration-fast) var(--ease-out); }
.sj-tab:hover { color: var(--text-primary); background: var(--surface-hover); }
.sj-tab:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.sj-tab--active { color: var(--text-accent); }
.sj-tab--active::after { content: ""; position: absolute; left: 0; right: 0; bottom: -1px; height: 2px;
  background: var(--accent); }
.sj-tab__count { font-size: var(--text-2xs); font-family: var(--font-mono); color: var(--text-tertiary);
  background: var(--gray-100); border-radius: var(--radius-full); padding: 1px 6px; }
.sj-tab--active .sj-tab__count { color: var(--accent-fg-on-subtle); background: var(--accent-subtle); }
```

### Props contract (`Tabs.d.ts`, verbatim)

```ts
/** Underline tabs for switching views within a screen. */
export interface TabsProps {
  items: Array<{ id: string; label: string; count?: number }>;
  /** id of the active tab. */
  active: string;
  onChange?: (id: string) => void;
}
export declare function Tabs(props: TabsProps): JSX.Element;
```

### Behavior (from `Tabs.prompt.md` + JSX)

- Underline style, indigo active indicator (2px `::after` bar overlapping the container's bottom
  border at `bottom: -1px`), optional mono count pills.
- ARIA: container `role="tablist"`, each tab a `<button role="tab" aria-selected={…}>`.
- Count pill renders when `count != null` (note: count `0` **is** rendered, unlike SidebarItem).
- Clicking a tab calls `onChange(item.id)`.

---

## 12. SidebarItem (`components/navigation/SidebarItem.jsx`)

### CSS (verbatim)

```css
.sj-sbitem { display: flex; align-items: center; gap: 8px; width: 100%; height: 30px;
  padding: 0 8px; border: none; background: transparent; cursor: pointer; text-align: left;
  font-family: var(--font-sans); font-size: var(--text-sm); color: var(--text-secondary);
  border-radius: var(--radius-sm);
  transition: background var(--duration-fast) var(--ease-out), color var(--duration-fast) var(--ease-out); }
.sj-sbitem:hover { background: var(--surface-hover); color: var(--text-primary); }
.sj-sbitem:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.sj-sbitem--active { background: var(--surface-selected); color: var(--accent-fg-on-subtle);
  font-weight: var(--weight-medium); }
.sj-sbitem--active:hover { background: var(--accent-subtle-hover); color: var(--accent-fg-on-subtle); }
.sj-sbitem__icon { display: inline-flex; flex: none; width: 16px; justify-content: center; }
.sj-sbitem__label { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sj-sbitem__count { font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--text-tertiary); }
.sj-sbitem--active .sj-sbitem__count { color: var(--accent-fg-on-subtle); font-weight: var(--weight-semibold); }
.sj-sbitem__dot { width: 8px; height: 8px; border-radius: var(--radius-full); flex: none; }
```

### Props contract (`SidebarItem.d.ts`, verbatim)

```ts
/** Sidebar navigation row — views, nested tags (depth), counts. */
export interface SidebarItemProps {
  /** Leading 16px Lucide icon. */
  icon?: React.ReactNode;
  /** Tag hue dot instead of icon (sidebar tag list). */
  dotColor?: "blue" | "teal" | "green" | "amber" | "orange" | "rose" | "purple" | "gray";
  label: string;
  /** Right-aligned mono count; hidden when 0. */
  count?: number;
  active?: boolean;
  /** Nesting level for tag hierarchies; indents 16px per level. */
  depth?: number;
  onClick?: () => void;
}
export declare function SidebarItem(props: SidebarItemProps): JSX.Element;
```

### Behavior (from `SidebarItem.prompt.md` + JSX)

- The 30px nav row used in every app sidebar — icon or tag-dot, label, mono count, indigo
  selected wash.
- Indentation formula (inline style): `paddingLeft: 8 + depth * 16` (px).
- Leading slot priority: `dotColor` (8px hue dot, `background: var(--tag-{dotColor}-dot)`, wrapped
  in the 16px icon slot) wins over `icon`; neither → no leading slot.
- Count renders only when `count != null && count !== 0` (**count 0 is hidden**, unlike Tabs).
- Label truncates with ellipsis.

---

## 13. Dialog (`components/feedback/Dialog.jsx`)

### CSS (verbatim)

```css
.sj-dialog-backdrop { position: fixed; inset: 0; background: rgba(20, 21, 29, 0.45); z-index: 1000;
  display: flex; align-items: flex-start; justify-content: center; padding: 9vh 16px 16px;
  animation: sjFadeIn var(--duration-fast) var(--ease-out); }
.sj-dialog { background: var(--surface-card); border-radius: var(--radius-lg); box-shadow: var(--shadow-lg);
  width: 100%; max-width: 440px; font-family: var(--font-sans); overflow: hidden;
  animation: sjDialogIn var(--duration-base) var(--ease-out); }
.sj-dialog--wide { max-width: 640px; }
.sj-dialog__head { display: flex; align-items: center; justify-content: space-between;
  padding: 14px 20px 0; }
.sj-dialog__title { font-size: var(--text-lg); font-weight: var(--weight-semibold);
  letter-spacing: var(--tracking-heading); color: var(--text-primary); }
.sj-dialog__close { border: none; background: transparent; cursor: pointer; color: var(--text-tertiary);
  width: 28px; height: 28px; border-radius: var(--radius-sm); display: flex; align-items: center;
  justify-content: center; }
.sj-dialog__close:hover { background: var(--surface-hover); color: var(--text-primary); }
.sj-dialog__body { padding: 12px 20px 20px; font-size: var(--text-sm); color: var(--text-secondary);
  line-height: var(--leading-normal); }
.sj-dialog__footer { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 20px;
  border-top: 1px solid var(--border-subtle); background: var(--gray-25); }
@keyframes sjFadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes sjDialogIn { from { opacity: 0; transform: translateY(-8px) scale(0.98); }
  to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) {
  .sj-dialog-backdrop, .sj-dialog { animation: none; }
}
```

### Props contract (`Dialog.d.ts`, verbatim)

```ts
/** Modal dialog — radius-lg, shadow-lg, footer on gray-25 well. Esc + backdrop close. */
export interface DialogProps {
  open: boolean;
  title: string;
  /** 640px instead of 440px (forms, pickers). */
  wide?: boolean;
  /** Footer actions, right-aligned (secondary then primary). */
  footer?: React.ReactNode;
  onClose?: () => void;
  children: React.ReactNode;
}
export declare function Dialog(props: DialogProps): JSX.Element | null;
```

### Behavior (from `Dialog.prompt.md` + JSX)

- Centered modal, **top-aligned at 9vh**, footer actions on a gray well. **Esc and backdrop
  close.**
- Footer order: secondary then primary (right-aligned, 8px gap).
- Returns `null` when `open` is false. While open, a document-level `keydown` listener fires
  `onClose()` on Escape; backdrop `mousedown` closes only when `e.target === e.currentTarget`
  (clicks inside the panel don't close).
- ARIA: panel has `role="dialog" aria-modal="true" aria-label={title}`.
- Close button (`aria-label="Close"`) renders only when `onClose` is provided. × glyph: 14×14 SVG,
  `stroke-width 2`, `<path d="M18 6 6 18M6 6l12 12">`.
- Footer well renders only when `footer` is set.

---

## 14. Toast (`components/feedback/Toast.jsx`)

### CSS (verbatim)

```css
.sj-toast { display: inline-flex; align-items: center; gap: 14px; min-height: 40px;
  padding: 8px 8px 8px 14px; background: var(--surface-inverse); color: var(--text-inverse);
  border-radius: var(--radius-md); box-shadow: var(--shadow-lg); font-family: var(--font-sans);
  font-size: var(--text-sm); animation: sjToastIn var(--duration-base) var(--ease-out); }
.sj-toast--fixed { position: fixed; left: 16px; bottom: 16px; z-index: 1100; }
.sj-toast__action { border: none; background: transparent; color: var(--indigo-300); cursor: pointer;
  font-family: inherit; font-size: var(--text-sm); font-weight: var(--weight-semibold);
  padding: 4px 8px; border-radius: var(--radius-sm); }
.sj-toast__action:hover { background: rgba(255, 255, 255, 0.1); color: var(--indigo-200); }
.sj-toast__x { border: none; background: transparent; color: var(--gray-400); cursor: pointer;
  width: 24px; height: 24px; border-radius: var(--radius-sm); display: flex; align-items: center;
  justify-content: center; padding: 0; }
.sj-toast__x:hover { background: rgba(255, 255, 255, 0.1); color: var(--gray-200); }
@keyframes sjToastIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .sj-toast { animation: none; } }
```

### Props contract (`Toast.d.ts`, verbatim)

```ts
/** Inverse-surface toast, bottom-left; the home of Undo. */
export interface ToastProps {
  message: string;
  /** e.g. "Undo" — setjoin prefers undo over confirmation dialogs. */
  actionLabel?: string;
  onAction?: () => void;
  onDismiss?: () => void;
  /** Fix to viewport bottom-left (default false renders inline). */
  fixed?: boolean;
}
export declare function Toast(props: ToastProps): JSX.Element;
```

### Behavior (from `Toast.prompt.md` + JSX)

- Dark gray-900 bar, bottom-left, indigo action link. Setjoin's pattern is **act-then-undo**:
  destructive/bulk mail actions show a Toast with "Undo" instead of asking first.
- `role="status"` on the container. `fixed` pins to viewport bottom-left (left/bottom 16px,
  z-index 1100); default renders inline.
- Action button renders when `actionLabel` is set; dismiss × (`aria-label="Dismiss"`) renders when
  `onDismiss` is set. × glyph: 12×12 SVG, `stroke-width 2`, `<path d="M18 6 6 18M6 6l12 12">`.

---

## SJIcon (shared icon wrapper)

`ui_kits/shared/SJIcon.jsx`, verbatim — the bundle's React-safe Lucide wrapper. In the SvelteKit
webmail this role is filled by `$lib/components/Icon.svelte` (lucide-svelte); the defaults below
(size 16, stroke-width 1.75) are the canonical icon metrics.

```jsx
// React-safe Lucide icon wrapper (vanilla lucide UMD). Exposes window.SJIcon.
// Avoids lucide.createIcons() DOM replacement, which fights React reconciliation.
function SJIcon({ name, size = 16, strokeWidth = 1.75, style, ...props }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!ref.current || !window.lucide || !lucide.icons[name]) return;
    ref.current.innerHTML = "";
    const el = lucide.createElement(lucide.icons[name]);
    el.setAttribute("width", String(size));
    el.setAttribute("height", String(size));
    el.setAttribute("stroke-width", String(strokeWidth));
    ref.current.appendChild(el);
  }, [name, size, strokeWidth]);
  return <span ref={ref} style={{ display: "inline-flex", width: size, height: size, flex: "none", ...style }} {...props}></span>;
}
window.SJIcon = SJIcon;
```

---

## Fonts (`tokens/fonts.css`)

Verbatim contents:

```css
/* setjoin webfonts.
   NOTE: No font binaries were provided with the brand. The system is designed
   around IBM Plex Sans + IBM Plex Mono, loaded from Google Fonts. If setjoin
   licenses dedicated font files later, replace this @import with @font-face
   rules pointing at local binaries. */
@import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap");
```

**Self-hosting replacement note**: the bundle loads IBM Plex Sans (400/500/600/700) and IBM Plex
Mono (400/500/600) from Google Fonts. Setjoin is an on-premise/air-gap product — production must
**not** depend on Google Fonts. Replace the `@import` with self-hosted `@font-face` rules pointing
at woff2 binaries under `mailserver/webmail/static/fonts/` (IBM Plex is OFL-licensed, so bundling
is permitted), preserving the same family names and weights so `--font-sans` / `--font-mono`
token definitions keep resolving. Include `font-display: swap` to match the bundle's
`display=swap` behavior.

---

## Brand assets

The four SVGs from `docs/design/setjoin-design-system/assets/` were copied **as files** (not
inlined) to `mailserver/webmail/static/brand/` on 2026-06-13, so they survive the bundle deletion
and are servable by the webmail at `/brand/<name>.svg`:

| File | Description |
|---|---|
| `mailserver/webmail/static/brand/logo-mark.svg` | 36×36 logo mark — two overlapping rounded squares (stroke `#1E202B`) with solid indigo `#4A50D0` intersection square; light-background color version. |
| `mailserver/webmail/static/brand/logo-mark-mono.svg` | 36×36 monochrome logo mark — same geometry, entirely `currentColor` (strokes + fill), for tinting via CSS color. |
| `mailserver/webmail/static/brand/logo-wordmark.svg` | 172×40 horizontal lockup — color mark + "setjoin" wordmark text (IBM Plex Sans 600, 22px, −0.02em): "set" in `#1E202B`, "join" in `#4A50D0`; for light backgrounds. |
| `mailserver/webmail/static/brand/logo-wordmark-dark.svg` | 172×40 dark-mode lockup — mark strokes `#FFFFFF`, intersection + "join" in light indigo `#A8AFF4`, "set" in `#FFFFFF`; for dark backgrounds. |

Note: `static/brand/` already contained pre-existing files (`glyph.svg`, `wordmark.svg`,
`app-icons/`) from earlier work; the four files above were added alongside them without
overwriting anything.
