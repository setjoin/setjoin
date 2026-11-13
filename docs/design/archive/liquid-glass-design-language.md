# SetJoin Liquid Glass — Cross-Platform Design Language

Date: 2026-06-02
Status: Complete (design). §1–5 concept / token mapping / strategy · §2 principles aligned to
Apple's 2026 HIG (Hierarchy · Harmony · Consistency) + product design philosophy (Deference to
Content, glass as material, meaningful motion, system integration, accessibility as architecture).
§6 components (incl. §6.1 action bars & content/control separation, §6.2 context menus &
power-user interactions) · §7 screens · §8 a11y (incl. §8.1 normative glass guardrails) · §9–10
air-gap / governance · §11 internationalization & Chinese support.
Direction (2026-06-02): **keep Liquid Glass + align to Apple's 2026 HIG.** Research confirms Liquid
Glass is NOT being phased out — iOS 27 will mandate it, the opt-out flag is being removed. Apple
is doubling down. The approach: make it *legible, accessible, and content-first* (§2: deference to
content, glass = material not decoration, native over hand-rolled). Evidence: Apple HIG iOS 26
(Hierarchy/Harmony/Consistency pillars); Gurman/Bloomberg confirms no redesign in iOS 27/macOS 27;
iOS 26.2/26.4 added transparency controls. Implementation phasing in the `toasty-jumping-kahn` plan.
Scope: Web (SvelteKit webmail) · Desktop (Tauri) · Mobile (SwiftUI iOS/iPadOS/macOS, Compose
Multiplatform Android) — one continuous design language across every SetJoin surface.

> **Where this fits.** The canonical *numeric* source of truth is
> `mailserver/webmail/src/lib/theme/tokens.css`. This document defines the *cross-platform
> semantics* of that system — how each CSS token becomes a native primitive on Apple and Android —
> so the three surfaces stay visually continuous. The web-only execution that established the
> system is recorded in [`setjoin-portal-liquid-glass-redesign.md`](./setjoin-portal-liquid-glass-redesign.md);
> the native build phasing is in [`phase12-client-architecture.md`](./phase12-client-architecture.md)
> (steps 12.3/12.5 reference this doc for *how*).

## Table of contents

1. Purpose, scope & governance
2. Principles
3. The token system (the shared vocabulary)
4. Cross-platform token mapping — CSS → SwiftUI → Compose
5. Glass vs. native-material strategy
6. Component patterns
7. Per-screen layout — Mail / Calendar / Contacts / Tasks
8. Accessibility per platform
9. Icons, colours & asset bundling *(revised 2026-06-02 — SF Symbols on Apple, Lucide on web)*
10. Governance & future codegen
11. Internationalization & Chinese support *(revised 2026-06-02 — CJK calibration, self-served bundles)*
12. Platform implementation references *(new — per-dependency API index, all verified 2026-06-02)*

---

## 1. Purpose, scope & governance

SetJoin ships one product across many surfaces. Without a shared design language each surface
drifts — exactly what happened on the web (the portal redesign found ~50 component styles
referencing an undefined "Prism" token vocabulary). This document prevents the same drift on
desktop and mobile **before** any native code is written.

**Governance — single source of truth, derived satellites:**

- `tokens.css` is the **canonical numeric source**. Every colour, radius, blur radius, duration,
  and the aurora gradient live there and nowhere else.
- This document defines the **semantics** — what each token *means* and which native primitive
  expresses it.
- Native token files (a SwiftUI `LiquidGlass` enum/asset catalog, a Compose `LiquidGlassTheme`)
  are **derived** from `tokens.css`, never independently authored. §10 recommends a codegen step
  so the numeric values never fork.

**Non-goals.** This is not an implementation guide for the apps themselves (that is Phase 12),
not a navigation/IA spec (that is `phase12-client-architecture.md` §Q6), and not a brand/voice
guide beyond what §2 restates.

## 2. Principles

Binding on every surface. Derived from Apple's 2026 HIG (Hierarchy · Harmony · Consistency),
the SetJoin product philosophy, and external evidence (see the `toasty-jumping-kahn` plan's
design-research note for citations).

### 2.1 Deference to Content (the Apple principle)

**Content is the hero. The interface must recede.** Chrome (sidebars, toolbars, tab bars) is
translucent glass *so the user sees through it to their mail, their calendar, their tasks* — not
so the glass itself draws attention. The aurora canvas is a soft atmospheric backdrop, never a
spectacle. When a user scrolls a message list, the toolbar should feel like it's not there.

> This is Apple's 2026 HIG "Deference" principle matured: the interface makes itself invisible
> so the user can focus on their work. Persistent toolbars that frame every view are the
> anti-pattern.

### 2.2 The glass ceiling

- **Glass is for floating chrome, never body content** — sidebars, toolbars, popovers, modals,
  docks, tab bars. Reading surfaces (message body, list content, compose area) are opaque.
- **Glass is a material, not a decoration** — it exists to create *spatial understanding* (this
  toolbar floats above the content), not visual flair. Apple's 2026 HIG calls this "material as
  interface" — surfaces that behave like physical materials in space.
- **The aurora canvas is the bottom layer** — a soft warm-cool mesh gradient. Glass chrome sits
  above it and lets it bleed through. This creates the spatial hierarchy: aurora (deepest) →
  opaque content (middle) → glass chrome (closest to the user).

### 2.3 Hierarchy — dynamic, content-aware

From Apple's 2026 HIG: *"Establish a clear visual hierarchy where controls elevate and distinguish
the content beneath them."*

- **Chrome adapts, not content.** Related actions are grouped (§6.1). Visual weight (opacity,
  blur strength, shadow depth) rises as the surface floats closer to the user: dock 0.40 →
  pane 0.55 → toolbar 0.72 → popover 0.85 → modal 0.92.
- **Per-app accents** — each module owns one hue (mail = blue, calendar = red, …). The active
  module tints interactive elements. This is the primary spatial cue for "where am I?"
- **Function-first, not a "simple mode"** *(revised 2026-06-01)* — the audience is sysadmins and
  power users; a stripped "simple" mode that hides controls is dead weight. There is **one full
  view** with all controls present. Density is managed by **collapsing chrome, not removing
  function**: a toggleable sidebar, collapsible panels/sections, and overflow ("More") menus —
  never a reduced feature set.

### 2.4 Harmony — native integration

From Apple's 2026 HIG: *"Align with the concentric design of hardware and software to create
harmony between interface elements, system experiences, and devices."*

- **Prefer the OS-native material wherever the platform provides one** (§5). On Apple platforms
  use `.glassEffect` / `Material` / `NSVisualEffectView` — these are the same materials every
  other app uses and they auto-respect Reduce Transparency, Increase Contrast, and Dark Mode.
  **Do not hand-roll glass on Apple** — it would look subtly wrong and double-pay for what the
  OS gives free.
- **System integration is not optional** — honour dark/light mode, Dynamic Type, Reduce Motion,
  Reduce Transparency, universal keyboard shortcuts, drag-and-drop. The app should feel like it
  shipped with the OS.
- **Fonts bundled, not downloaded** — Inter (SF Pro substitute), Inter Tight (display), Noto
  Sans SC (中文), JetBrains Mono (identifiers). All shipped in the binary (§9). No CDN, no
  Google Fonts — this is both an air-gap requirement and a system-integration choice (the OS
  doesn't fetch fonts from the internet).

### 2.5 Consistency — adaptive, not uniform

From Apple's 2026 HIG: *"Adopt platform conventions to maintain a consistent design that
continuously adapts across window sizes and displays."*

- **One design language, three surfaces, one canonical source** — `tokens.css` is the numeric
  source of truth (§3). Web, desktop, and mobile all derive from it. The language is identical;
  the *expression* adapts: CSS `backdrop-filter` on web, native `.glassEffect` on Apple,
  synthetic `RenderEffect` blur on Android.
- **Lucide icons everywhere for cross-platform parity** — one glyph set means an icon reads
  identically on web, desktop, and mobile. SF Symbols are permitted **only** for genuine
  OS-chrome affordances on Apple (§9).

### 2.6 Meaningful Motion

From Apple's HIG: *"Animations should not be flashy. They must serve to provide physical context."*

- **One spring curve** — `cubic-bezier(0.32, 0.72, 0, 1)`, the macOS spring (§3, §4.6).
  Reproduced exactly on every platform. Do not substitute a platform-default spring.
- **Four durations, one purpose each** — 120ms hover (immediate feedback), 200ms state (toggle,
  press), 320ms panel (open/close, expand/collapse), 480ms sheet (modal present/dismiss).
- **Motion is spatial, not decorative** — a panel slides in from the right because it *lives*
  to the right of the list. A modal scales up from its origin because the user *summoned* it.
  The animation teaches the spatial model.

### 2.7 Voice & polish

- **Voice** — calm, technical, sentence case, no exclamation marks, no emoji in product chrome.
  Sysadmins are the audience. State what happened, then what to do.
- **Hairlines, not borders** — `1px solid var(--hairline)` separates content regions, not heavy
  boxes. Glass edges use `var(--glass-edge)` for a darker contact shadow.
- **Icons are semantic, not decorative** — every icon communicates function. No icon appears
  without a label (visible or `aria-label`).

### 2.8 Accessibility as architecture

From Apple's 2026 HIG: accessibility is now treated as a **non-optional, foundational requirement**
— not a bolt-on feature.

- **WCAG 2.2 AA is the floor** — 4.5:1 body text, 3:1 large text / UI affordances. Every glass
  surface carries a semi-opaque fill behind text so contrast never depends on blur (§8.1).
- **Reduce Transparency / Reduce Motion are normative** — when the OS requests either, glass
  surfaces fall back to opaque `--surface-*` and the spring is dropped. Not "best effort."
- **Dynamic Type** — text scales with the user's system preference. Layouts size to content,
  never hardcode widths (§11.5).

## 3. The token system (the shared vocabulary)

The families below are the complete contract. Values are quoted from `tokens.css` (light /
dark). Native layers reproduce these exact values.

### Type
- Families: `--font-sans` (Inter, Noto Sans SC) · `--font-display` (Inter Tight) · `--font-mono`
  (JetBrains Mono). All **bundled** — no CDN (§9).
- Scale (size / line-height, px): `display` 56/64 · `h1` 32/40 · `h2` 24/32 · `h3` 18/26 ·
  `body` 14/22 · `small` 12/18 · `mono` 13/20.
- Weights: 400 / 500 / 600 / 700. Inter alt features on: `ss01`, `cv11`, `cv05`; optical sizing auto.

### Spacing & radii
- Spacing: 4px base ladder `--s-0`…`--s-12` = 0/2/4/6/8/12/16/20/24/32/40/56/72.
- Radii: `--r-1` 6 (chips/badges) · `--r-2` 8 (inputs/buttons/list rows) · `--r-3` 10 (small
  cards) · `--r-4` 14 (panels/cards) · `--r-5` 20 (sheets/modals) · `--r-6` 24 (dock) ·
  `--r-full` 999.

### Surfaces & neutrals
| | Light | Dark |
|---|---|---|
| `--bg` | `#FFFFFF` | `#000000` (OLED) |
| `--surface-1/2/3` | `#FFFFFF` / `#F5F5F7` / `#ECECEE` | `#15161B` / `#1B1C22` / `#2A2B30` |
| `--fg-1/2/3/4` | `#1D1D1F` / `#424246` / `#6E6E73` / `#A1A1A6` | `#F5F5F7` / `#C7C7CC` / `#8E8E93` / `#5A5A5F` |
| `--hairline` / `-strong` | `rgba(0,0,0,.08)` / `.14` | `rgba(255,255,255,.10)` / `.18` |

### Glass
- Opacity ladder (background alpha rises as the surface floats higher): `--glass-dock-bg` 0.40 →
  `--glass-pane-bg` 0.55 → `--glass-toolbar-bg` 0.72 → `--glass-popover-bg` 0.85 →
  `--glass-modal-bg` 0.92. Light base `rgba(255,255,255,…)`; dark base `rgba(22,24,30,…)`
  (popover `28,30,38`; modal `20,22,28`; dock pure black).
- `--glass-border` (top highlight), `--glass-edge` (bottom contact), `--glass-inner-light`
  (the inset refractive highlight — two inset shadows).
- Blur: `--blur-light` `blur(20px) saturate(180%)` · `--blur` `blur(40px) saturate(180%)` ·
  `--blur-heavy` `blur(60px) saturate(200%)`.
- Shadows: `--shadow-pane` / `--shadow-popover` / `--shadow-modal` — each a two-layer stack
  (tight contact + soft ambient), darker in dark mode.

### Colour
- 12 system accents (`--c-*`): blue/violet/green/teal/orange/red/indigo/pink/gray/yellow/mint/brown.
  Light values are the macOS palette; dark values are the iOS dark palette (more saturated, e.g.
  `--c-blue` `#0066CC` → `#0066FF`, `--c-violet` `#AF52DE` → `#BF5AF2`).
- Semantic: `--accent` (= `--c-blue`) + `--accent-hover/press/soft/ring`; `--success`/`--warn`/
  `--danger`/`--info`.
- 9 per-app accents: `--app-mail` blue · `--app-auth` violet · `--app-drive` green ·
  `--app-chat` teal · `--app-meet` orange · `--app-calendar` red · `--app-erp` indigo ·
  `--app-oa` pink · `--app-admin` gray.
- Status dots: online/busy/away/offline → green/red/orange/gray.

### Motion
- `--ease` = `cubic-bezier(0.32, 0.72, 0, 1)` — the one macOS spring, used for everything.
- Durations: `--d-hover` 120ms · `--d-state` 200ms · `--d-panel` 320ms · `--d-sheet` 480ms.

### Aurora wallpaper
`--wallpaper-aurora` = four corner `radial-gradient`s over a `linear-gradient` base.
- Light: blue `rgba(120,165,255,.55)` @12%/8%, pink `rgba(255,180,220,.45)` @88%/12%, warm
  `rgba(255,215,170,.55)` @70%/92%, blue `rgba(180,220,255,.50)` @18%/88%; base `#EEF1F7`→`#F5F5F7`.
- Dark: deeper anchors (`60,100,200` / `160,70,200` / `200,110,60` / `40,100,180`); base
  `#060812`→`#0B0B0F`.

### Dark mode trigger
`@media (prefers-color-scheme: dark)` applied to `:root:not(.light)`, plus an explicit
`:root.dark` override class (and a `:root.light` opt-out). Native layers mirror this: a
system-following default with a user override.

## 4. Cross-platform token mapping — CSS → SwiftUI → Compose

The heart of the spec. SwiftUI targets iOS 26 / iPadOS 26 / macOS Tahoe; Compose targets Android
(Compose) and, where used, Compose Multiplatform desktop. **Tauri desktop is not a column** — its
webview renders the webmail and therefore consumes the CSS column directly (its only native
concern is the window frame, see §5).

### 4.1 Glass surfaces
| | Web (CSS) | SwiftUI | Compose |
|---|---|---|---|
| Mechanism | `backdrop-filter: var(--blur)` + `background: var(--glass-*-bg)` + `box-shadow: var(--glass-inner-light)` + `1px var(--glass-border)` | **Native** `.glassEffect(.regular, in:)` (iOS 26) or `Material` ladder; macOS `NSVisualEffectView` vibrancy | **Custom-render**: `Modifier.blur(radius)` backed by `RenderEffect.createBlurEffect` (API 31+) **or** the Haze library, + a 1px gradient-border overlay reproducing `--glass-inner-light` |
| Opacity ladder → | dock .40 / pane .55 / toolbar .72 / popover .85 / modal .92 | `.ultraThinMaterial` / `.thinMaterial` / `.regularMaterial` / `.thickMaterial` / `.thickMaterial`+opaque scrim | blur radius + Material 3 `surfaceColorAtElevation` tint at matching alpha; modal → near-opaque scrim |
| Highlight/edge | `--glass-border` + `--glass-edge` | implicit in the material; add a `.strokeBorder` only on macOS panes | explicit `Brush.verticalGradient` 1px border (top light → bottom dark) |
| Fallback | n/a (always supported) | material auto-falls-back under Reduce Transparency | **mandatory** solid `--surface-*` fill when API < 31 / battery-saver / Reduce Transparency (§8) |

### 4.2 Blur levels
| Web | SwiftUI | Compose |
|---|---|---|
| `--blur-light` 20px / sat 180% | `.thinMaterial` (or `.ultraThin` on dense chrome) | `blur(8.dp)` + `ColorMatrix` saturation ×1.8 |
| `--blur` 40px / sat 180% | `.regularMaterial` | `blur(16.dp)` + sat ×1.8 |
| `--blur-heavy` 60px / sat 200% | `.thickMaterial` | `blur(24.dp)` + sat ×2.0 |

(dp values are visual equivalents — the CSS px and Compose dp blur scales are not 1:1; calibrate
against the previews in §6/S3.)

### 4.3 Aurora wallpaper
| Web | SwiftUI | Compose |
|---|---|---|
| `--wallpaper-aurora` (4 radial + linear) painted on `body` | `MeshGradient` (iOS 18 / macOS 15) with the four corner colours over a base fill; back-deploy = four `RadialGradient`s layered in a `ZStack` | layered `Brush.radialGradient` in a full-bleed `Box` background, or an AGSL `RuntimeShader` (API 33+) for the smoothest blend |
| Light/dark | two anchor sets | two `MeshGradient` colour arrays keyed off `colorScheme` | two brush sets keyed off `isSystemInDarkTheme()` |

The aurora is **static** (no animation) on all surfaces — it is a canvas, not motion.

### 4.4 Colour & accents

| Web | SwiftUI | Compose |
|---|---|---|
| `--c-*` + `--app-*` CSS vars (light/dark blocks) | **System semantic colours first** — `.foregroundStyle(.primary)`, `.tint(.blue)`, `Color(.systemBackground)`. Our token values define asset catalog colour sets; the app consumes them through the semantic API, not hardcoded hex (§9.2). Exposed via `LiquidGlass.Accent` enum. | `LiquidGlassColors` data class via `CompositionLocal`, light/dark instances; Material 3 `ColorScheme` seeded from `--accent` |
| Active-module tint | the module sets `--accent` to its `--app-*` | the app sets `.tint(module.accent)` | the nav host swaps `LiquidGlassColors.accent` |
| Semantic | `--success/warn/danger/info` | `.tint(.green)` / `.tint(.orange)` / `.tint(.red)` — the system colours, matched to our token values | `ColorScheme.error` / custom semantic colours |

### 4.5 Typography
| Web | SwiftUI | Compose |
|---|---|---|
| Bundled `@font-face` (Inter / Inter Tight / Noto Sans SC / JetBrains Mono) | register custom fonts; map the px scale to Dynamic Type via `.font(.custom(_, size:, relativeTo:))` — display→`.largeTitle`, h1→`.title`, h2→`.title2`, h3→`.headline`, body→`.body`, small→`.caption`, mono→custom monospaced | `FontFamily(Font(R.font.inter_*))`; a `Typography` whose styles carry the sp sizes |
| Sizing rule | px | px ≈ **pt** at base scale; let Dynamic Type scale up | px ≈ **sp** at base scale; sp honours user font scale |
| Weights | 400/500/600/700 | `.regular/.medium/.semibold/.bold` | `FontWeight.Normal/Medium/SemiBold/Bold` |

### 4.6 Motion
| Web | SwiftUI | Compose |
|---|---|---|
| `--ease` `cubic-bezier(0.32,0.72,0,1)` | **exact** `Animation.timingCurve(0.32, 0.72, 0, 1, duration:)`, wrapped as `LiquidGlass.spring(_:)` | **exact** `CubicBezierEasing(0.32f, 0.72f, 0f, 1f)`, wrapped as `LiquidGlassEasing` |
| `--d-hover` 120 / `--d-state` 200 / `--d-panel` 320 / `--d-sheet` 480 | `duration: 0.12 / 0.20 / 0.32 / 0.48` | `tween(120 / 200 / 320 / 480, easing = LiquidGlassEasing)` |

The curve is reproduced **exactly** on all platforms — it is the signature of the system. Do not
substitute a platform-default spring.

### 4.7 Radii, spacing, shadows
| Web | SwiftUI | Compose |
|---|---|---|
| `--r-*` | `RoundedRectangle(cornerRadius:)` / `.clipShape` / `.glassEffect(in: .rect(cornerRadius:))` | `RoundedCornerShape(dp)` |
| `--s-*` | spacing constants on a `Spacing` enum | `Dp` tokens on a spacing object |
| `--shadow-*` (two-layer) | two stacked `.shadow(...)` modifiers (tight + ambient) | `Modifier.shadow(elevation, shape)` (single — approximate the ambient layer) |

### 4.8 Dark mode
| Web | SwiftUI | Compose |
|---|---|---|
| `prefers-color-scheme` on `:root:not(.light)` + `.dark`/`.light` overrides | `@Environment(\.colorScheme)` for default + `.preferredColorScheme(_)` for the user override; asset catalog supplies dark values automatically | `isSystemInDarkTheme()` for default + an app override state; `LiquidGlassColors`/`ColorScheme` swap accordingly |

Dark glass uses the darker rgba bases (§3); dark accents are the more-saturated iOS palette;
the dark aurora uses the deep anchor set over `#060812`.

## 5. Glass vs. native-material strategy

The load-bearing rule that keeps the language continuous *and* native on each platform: **prefer
the OS-native material wherever the platform provides one; synthesise glass only where it does
not.**

- **Apple (iOS 26 / iPadOS 26 / macOS Tahoe).** Use the system materials / Liquid Glass directly
  (`.glassEffect`, `Material`, `NSVisualEffectView`). These *are* the same visual language Apple
  ships in Tahoe/iOS 26, they match every other app on the device, and they auto-respect Reduce
  Transparency and Increase Contrast. **Do not hand-roll blur on Apple** — it would look subtly
  wrong and double-pay for what the OS gives free.
- **Tauri desktop.** The window *content* is the webmail webview, so glass there is the CSS
  `backdrop-filter` already shipping (works in WKWebView / WebView2 / WebKitGTK). The window
  *frame* uses Tauri 2's built-in native APIs: macOS `TitleBarStyle::Transparent` (traffic lights
  preserved, titlebar area becomes transparent so the webview's CSS aurora + glass toolbar bleed
  to the top edge), Windows 11 Mica / Acrylic via `windowEffects` config in `tauri.conf.json`, and
  Linux blur where the compositor supports it (graceful solid fallback otherwise). Result: desktop
  inherits the entire web design language for free and adds only a transparent native frame.
  **No extra crates needed** — Tauri 2's `WebviewWindowBuilder` + `windowEffects` config replace
  the deprecated `window-vibrancy` crate approach. See `docs/plans/desktop-native-chrome.md` for
  the implementation plan. ([Tauri v2 Window Customization](https://v2.tauri.app/learn/window-customization/))
- **Android (Compose).** The only surface with no first-class glass primitive. Here we synthesise:
  `RenderEffect` blur (API 31+) + a gradient-border overlay for the inner-light highlight. A
  **solid-surface fallback is mandatory** (API < 31, battery saver, Reduce Transparency) and uses
  the `--surface-*` tokens at full opacity. Calibrate the synthetic glass against the regenerated
  `mobile-preview.html` (S3) so it reads as the same material as Apple's.

---

## 6. Component patterns

Each canonical CSS class (verified present in `mailserver/webmail/src/app.css` /
`tokens.css`) maps to a native equivalent. **The "glass = chrome only" rule governs:** the
`.glass-*` classes become native *materials*; content classes (`.card`, `.data-table` rows,
`.alert`) become *opaque* surfaces — they are never glass.

| Canonical CSS | Role | SwiftUI | Compose |
|---|---|---|---|
| `.btn--primary` | filled accent, `--r-2` | `Button{}.buttonStyle(.borderedProminent).tint(accent)`; iOS 26 capsule may take `.glassEffect` | `Button(colors = buttonColors(containerColor = accent))` |
| `.btn--secondary` | `--surface-3` fill | `.buttonStyle(.bordered)` | `FilledTonalButton` |
| `.btn--ghost` | transparent, `--accent-soft` hover | `.buttonStyle(.borderless).tint(accent)` | `TextButton` |
| `.btn--destructive` | `--danger` fill | `Button(role: .destructive)` / `.tint(.red)` | `Button(containerColor = error)` |
| `.input` | hairline border, `--accent-ring` focus | `TextField` + rounded-border style, `--r-2` | `OutlinedTextField` |
| `.chip` / `.chip--accent` | `--r-1` pill | custom capsule / `FilterChip` | `AssistChip` / `FilterChip` |
| `.badge` | count/status dot | `.badge(_)` | `Badge` |
| `.card` | **opaque** content card, `--r-4` | plain card (no material) | `ElevatedCard` / `Card` |
| `.data-table` rows | **opaque** list rows, `--r-2` | `List` / `Table` rows | `LazyColumn` + `ListItem` |
| `.alert` | semantic banner | inline banner tinted `--warn/--danger/--info` | `Card` with semantic container tint |
| `.glass-toolbar` | toolbar (.72) | `.toolbarBackground(.regularMaterial)` | `TopAppBar` over synth-glass surface |
| `.glass-pane` | sidebar/floating pane (.55) | `.background(.thinMaterial)` / split-view sidebar | `NavigationRail` / pane over synth glass |
| `.glass-popover` | popover/menu (.85) | `.presentationBackground(.thickMaterial)` / `Menu` | `DropdownMenu` / popup over synth glass |
| `.glass-modal` / `.modal-sheet` | modal/sheet (.92) | `.sheet { … }.presentationBackground(.thinMaterial)` | `ModalBottomSheet` / `AlertDialog` (synth glass scrim) |
| `.glass-dock` | floating dock/tab bar (.40) | `TabView` (material tab bar) / floating capsule | `NavigationBar` over synth glass |

Buttons, chips, inputs all carry the `--accent` of the active module; focus rings use
`--accent-ring`; corners use the radius noted in §3. Motion on press/hover uses
`LiquidGlass.spring` at `--d-hover`/`--d-state` (§4.6).

### 6.1 Action bars & content/control separation

Actions on a record (a message, an event, a contact) live in **one bounded toolbar**, visually
separated from the content they act on — never scattered, never floated into a corner. The
ordering convention, consistent across web/desktop/mobile:

```
[ primary actions ]   [ secondary actions ]        · · · ·        [ destructive ]
  Reply Reply-all       Snooze Flag Move                               Delete
  Forward
```

- **Primary** (the expected next step — Reply / Reply-all / Forward) lead, grouped together; the
  single most likely action may be `.btn--primary`, the rest `.btn--secondary`/`.btn--ghost`.
- **Secondary** (Snooze, Flag, Move) follow as a group.
- **Destructive** (Delete) is the only action set apart — pushed to the trailing edge with a
  spacer/divider so it can't be hit by accident — but it stays **inside the same toolbar**, not
  exiled to an unrelated corner.
- **Destructive** (Delete) is the only action set apart — pushed to the trailing edge with a
  spacer/divider so it can't be hit by accident — but it stays **inside the same toolbar**, not
  exiled to an unrelated corner.
- **Content vs. control separation is explicit:** the action bar is a distinct chrome region —
  a `.glass-toolbar` strip with a hairline/edge — clearly demarcated from the opaque reading
  surface above it. The reader should never wonder which pixels are content and which are buttons.

Native: SwiftUI `.toolbar` placements (`.primaryAction` / `.secondaryAction` / `.destructiveAction`)
encode exactly this grouping; Compose `TopAppBar`/`BottomAppBar` actions + an overflow menu do the
same. On phones, secondary/destructive actions collapse into an overflow ("More") menu rather than
crowding the bar.

### 6.2 Context menus & power-user interactions

The audience is power users; the design must reward them with fast, productive interactions —
the toolbar is the floor, not the ceiling. Every record (message, contact, event, task) exposes a
**context menu** and supports **multi-select bulk actions** and **keyboard control**.

- **Context menu** — right-click (desktop/web), long-press (iOS/Android) on a record opens a
  `.glass-popover` menu with that record's verbs plus power actions: *Reply · Snooze ·
  Move to… · Add label · Mute thread · Block sender · **Create rule…** · Delete*. It is glass
  chrome, so §8.1 guardrails apply.
- **Rule-from-message (flagship flow)** — "Create rule…" opens a rule sheet **pre-filled from the
  message** (e.g. `From: alice@setjoin.com` → action `Add tag "Finance"` / `Move to Finance`).
  On save, the system offers a **retroactive bulk apply**: *"Apply this rule to the 42 matching
  messages already in your inbox?"* → on confirm, it runs the bulk action with a progress
  indicator and a single **Undo**. This is the Outlook/Gmail "create rule → also clean up existing
  mail" pattern, made one continuous flow.
- **Multi-select & bulk actions** — checkbox / shift-click / ⌘-click selects a range; a
  **contextual bulk bar** then replaces the normal toolbar (selection count + Tag ·
  Move · Mark read · Delete), following the §6.1 grouping. Escape / deselect restores the toolbar.
- **Keyboard-first** — Gmail-style single-key shortcuts (`r` reply, `l` label, `s` star, `f` flag,
  label, `s` star, `j`/`k` nav), and a **command palette** (`⌘K` / `Ctrl-K`) that can invoke any
  action or jump to any module — the power-user fast path.
- **Undo everywhere** — destructive and bulk actions surface a transient undo affordance (ties to
  the existing undo/snooze work) so power moves stay safe.

Native mapping: SwiftUI `.contextMenu` + `.swipeActions` + `.keyboardShortcut` and a command-palette
sheet; Compose long-press `DropdownMenu` / contextual action mode + key handlers. Cross-platform the
*entry points* differ (right-click vs. long-press) but the **action set and the rule-from-message
→ bulk-apply flow are identical**.

## 7. Per-screen layout — Mail / Calendar / Contacts / Tasks

The layering is identical on every surface: **aurora canvas (bottom) → glass navigation chrome →
opaque content panes**. Navigation containers come from `phase12-client-architecture.md` §Q6
(`NavigationSplitView` on macOS/iPadOS, bottom `TabView` on iOS, `NavigationDrawer` on
Android/Compose-desktop); this section adds only the visual layering, not the IA.

**Form-factor skeleton (all modules share it):**

| Form factor | Chrome (glass) | Content (opaque) |
|---|---|---|
| Phone | bottom tab bar (`.glass-dock`) + top bar (`.glass-toolbar`); push navigation | single full-bleed column; aurora peeks at safe-area edges |
| Tablet / iPad | split-view sidebar (`.glass-pane`) + toolbar | 2 columns (list ∣ detail) on opaque surfaces |
| Desktop (macOS native / Tauri) | vibrant window frame (§5) + sidebar + toolbar | full 3 columns (nav ∣ list ∣ detail) |

**Per module (the list ∣ detail content; nav rail is shared):**

- **Mail** — sidebar: folders/labels/tags. List: message rows (`.data-table`, opaque). Detail:
  reading pane (opaque); compose opens as `.glass-modal` (desktop) or full sheet (phone).
- **Calendar** — sidebar: calendars + mini-month. Content: month/week grid (opaque). Event
  open/edit as `.glass-popover` (desktop) or sheet (phone). Accent = red (`--app-calendar`).
- **Contacts** — sidebar: groups/GAL. List: contact rows. Detail: contact card (`.card`, opaque).
- **Tasks** — sidebar: lists. Content: list view or Kanban board (opaque columns). Task detail
  as popover/sheet. Drag uses `LiquidGlass.spring` at `--d-panel`.

Module switching (the launcher / app switcher) is itself a `.glass-popover`/`.glass-dock`
surface; switching modules swaps the active `--app-*` accent (§4.4).

## 8. Accessibility per platform

| Concern | Web | SwiftUI | Compose |
|---|---|---|---|
| Reduce Transparency | `@media (prefers-reduced-transparency)` → swap `--glass-*-bg` to solid `--surface-*` | system materials auto-adapt; also honour `UIAccessibility.isReduceTransparencyEnabled` | reuse the §5 solid fallback (`--surface-*` at full opacity) |
| Reduce Motion | `@media (prefers-reduced-motion)` → drop the spring, snap instantly | `@Environment(\.accessibilityReduceMotion)` → no `timingCurve` | check accessibility settings → `snap()` instead of `tween` |
| Dynamic Type / font scale | `rem` + `clamp()` | Dynamic Type via `relativeTo:` (§4.5); cap on dense chrome | `sp` honours user scale; cap on dense chrome |
| Contrast over glass | text uses `--fg-1/2`; chrome uses **higher-opacity** glass (toolbar .72 > pane .55) so AA holds over the busy aurora | same opacity discipline; Increase Contrast → strengthen `--hairline-strong`, raise glass opacity | same; raise synth-glass alpha + border under high-contrast |
| Screen reader | Voiceover/labels on every control; glass is decorative (not announced); modal focus trap + `Escape` | accessibility labels; glass `.accessibilityHidden(true)` | `contentDescription`; `Modifier.semantics` |

Target **WCAG 2.2 AA**: 4.5:1 body text, 3:1 large text / UI affordances. The opacity ladder
exists partly for this — chrome that carries text floats at higher opacity than decorative panes.

### 8.1 Glass guardrails (normative)

Translucency must never cost legibility. iOS 26 itself drew legibility criticism and Apple
walked the glass *back* across betas toward higher contrast — so these are hard rules, not
suggestions:

1. **Contrast floor.** Text and interactive affordances over any glass surface must meet WCAG 2.2
   (4.5:1 body, 3:1 large/UI) in both light and dark, measured against the *effective* composited
   background, not the token in isolation.
2. **Contrast never depends on blur.** Every glass surface carries a **semi-opaque fill** beneath
   text (the opacity ladder in §3 — toolbar 0.72, popover 0.85, modal 0.92 — exists for this).
   Blur is decoration on top of a legible fill, never the thing that makes text readable.
3. **Blur ceiling.** Reserve `--blur` (40px) and `--blur-heavy` (60px) for large modal / sheet
   chrome; **default toolbars, docks, and dense chrome to `--blur-light` (20px)**. Heavy blur on
   small, text-dense chrome is the failure mode accessibility audits flag.
4. **Reduced-transparency / reduced-motion are normative.** When the OS requests either, glass
   surfaces fall back to **opaque `--surface-*`** and the spring is dropped — not "best effort."
   On Apple the system materials do this automatically; on Android and web it is implemented
   explicitly (§4.1, §5).
5. **Glass is chrome only, used with intent** — modals, popovers, toolbars, docks, sidebars —
   never body/reading content and never as a global wash. This matches the published
   accessible-glass consensus, not just our taste.

> Evidence: WCAG 2.2; Apple's iOS 26 → 26.2 contrast walk-back; and the accessible-glassmorphism
> guidance (semi-opaque fills, blur limits, `prefers-reduced-transparency`) from Axess Lab / IxDF.
> See the design-research note in the `toasty-jumping-kahn` plan for citations.

## 9. Icons, colours & asset bundling

SetJoin must run fully air-gapped (Phase 12 Q3). The design language inherits a hard constraint:
**every visual asset ships inside the binary; nothing loads from a CDN.**

### 9.1 Icons — SF Symbols on Apple, Lucide everywhere else

**Revised 2026-06-02.** The original "Lucide everywhere for parity" rule underweights the
§2.4 Harmony principle (native integration). Apple's HIG is unambiguous: *"Before designing a
custom icon, exhaustively search the SF Symbols app."* SF Symbols give us free weight-matching
to San Francisco, Dynamic Type scaling, 7-weight support, and native rendering. The updated
rule:

| Platform | Icon library | Rationale |
|---|---|---|
| **iOS / iPadOS / macOS** | **SF Symbols** (primary); Lucide (fallback for concepts with no symbol) | Native integration (§2.4). System icons follow the user's preferred weight, adapt to Dynamic Type, and render natively. |
| **Web (SvelteKit)** | **Lucide** (MIT, bundled as SVG sprite) | No SF Symbols on web. Lucide is the cross-platform reference set — every icon in the preview mockups is Lucide. |
| **Android (Compose)** | **Material Icons** (primary); Lucide (fallback) | Material Icons match Compose's native look. **Bundled in the APK, not CDN-fetched** — Material Symbols is included with the OS on Android 12+, and bundled as a font asset for older devices. Lucide fills gaps. |
| **Tauri desktop** | **Lucide** (webview inherits Lucide from the bundled webmail) | The desktop webview renders the webmail directly — Lucide comes with it. |

**Rule:** on any Apple surface, *search SF Symbols first*. If a concept has no symbol or the
symbol's metaphor is wrong for the action, use a custom Lucide glyph matching SF Symbol weight
(Regular, 17pt default) and optical grid. Never ship raster PNG icons — all glyphs are vectors.

### 9.2 Colours — semantic system colours on Apple, our tokens on web

Our 12-colour accent palette (`--c-blue`/`--c-violet`/…) *is* the iOS/macOS system palette
(§3). The numeric values match Apple's Light and Dark appearances explicitly. The refinement:
**on Apple platforms, deliver these colours through the system's semantic colour API rather
than hardcoded hex values.**

| Semantic purpose | Apple API | Our CSS token (canonical reference) |
|---|---|---|
| Primary text | `.foregroundStyle(.primary)` / `Color(.label)` | `--fg-1` |
| Secondary text | `.foregroundStyle(.secondary)` | `--fg-2` |
| Tertiary text | `.foregroundStyle(.tertiary)` | `--fg-3` |
| Disabled text | `.foregroundStyle(.quaternary)` | `--fg-4` |
| Page background | `Color(.systemBackground)` | `--surface-1` |
| Secondary background | `Color(.secondarySystemBackground)` | `--surface-2` |
| Tertiary fill | `Color(.tertiarySystemFill)` | `--surface-3` |
| Accent / tint | `.tint(.blue)` | `--accent` / `--c-blue` |
| Success | `.tint(.green)` | `--success` / `--c-green` |
| Warning | `.tint(.orange)` | `--warn` / `--c-orange` |
| Danger | `.tint(.red)` | `--danger` / `--c-red` |

**Rationale:** Apple's semantic colours automatically adapt to Light/Dark, Increased Contrast,
and Reduce Transparency — they are *context-aware*, not static hex values. Hardcoding
`#0066CC` on iOS bypasses this machinery and produces colours that look subtly wrong in
accessibility modes. The CSS tokens remain the canonical **numeric reference** (used directly
on web and Android, and as the definition for asset catalog colour sets on Apple).

### 9.3 Air-gap asset bundling

- **Fonts** — Inter, Inter Tight, Noto Sans SC, JetBrains Mono bundled on every surface (web
  `@font-face` from local files; iOS app bundle + `UIAppFonts`; Android `res/font`). No Google
  Fonts, no `fonts.googleapis.com`.
- **Aurora & glass** are rendered (CSS gradients / `MeshGradient` / shaders), never image
  assets — so there is nothing to download and they scale to any display.
- **SF Symbols** are a system framework, not a download — they ship with the OS. No bundling
  needed. Lucide SVGs (web) and Material Icons (Android) are bundled in each binary.

## 10. Governance & future codegen

- `tokens.css` is the **single canonical numeric source**. SwiftUI and Compose token files are
  **derived**, never independently authored.
- **Recommended follow-up (out of scope here):** a codegen script (e.g.
  `scripts/gen-design-tokens.ts`) that parses `tokens.css` and emits `LiquidGlassTokens.swift`
  (`Color` / `CGFloat` / `Animation` constants) and `LiquidGlassTokens.kt` (Compose `Color` /
  `Dp` / `Easing`). Wire it into CI to **fail the build if the native token files are stale**
  versus `tokens.css`. This guarantees the numeric source can never fork.
- **Until codegen exists:** any change to `tokens.css` must update the derived native files in the
  same change set, called out in the description.
- **Versioning:** record a design-system version in a `tokens.css` header comment; bump it on any
  breaking visual change so native layers can pin and migrate deliberately.

## 11. Internationalization & Chinese support *(revised 2026-06-02 — CJK calibration, self-served bundles)*

SetJoin ships **Simplified Chinese (zh-CN, 中文)** as a first-class language alongside English and
German — required for the Chinese market (see `../platform/stage1-chinese-i18n.md` and Phase 12
§12.7 "i18n en/zh/de"). The design language treats locale as a first-class, cross-platform concern.

### 11.1 Locale model (existing web framework)

The webmail already has a lightweight i18n runtime at `mailserver/webmail/src/lib/i18n/index.ts`:
`Locale = 'en' | 'de' | 'zh'`; per-locale `META` (display name, direction, first-day-of-week,
ICU date/number formats); `t()` lookup with ICU plural/select; `setLocale()` (persists to
`localStorage`, sets `document.documentElement.lang`/`dir`, dynamic-imports the bundle);
`Intl`-backed `formatDate` / `formatNumber` / `formatRelativeTime`. **`zh` is fully modelled**
(`displayName: '中文'`, `direction: 'ltr'`, `firstDayOfWeek: 1` Monday, CJK formats `y年M月d日`,
`zh-CN` Intl code). Native layers mirror this model.

### 11.2 Locale detection — the rule (auto-switch to Chinese)

Resolution order, identical in spirit on every surface:

1. **Explicit persisted choice** (user picked a language before) — wins always.
2. **System / browser language** — if the preferred language **starts with `zh`** (`zh`,
   `zh-CN`, `zh-Hans`, `zh-SG`, `zh-TW`, `zh-Hant`) → **Chinese**; `de*` → German; else step 3.
3. **English** default.

| Surface | Signal | Persisted choice |
|---|---|---|
| Web | `navigator.languages` / `navigator.language` (≈ `Accept-Language`) | `localStorage['locale']` |
| Desktop (Tauri) | OS locale (`@tauri-apps/plugin-os` `locale()`), or the webview `navigator.language` | app config store |
| iOS / macOS | `Locale.preferredLanguages.first` | `UserDefaults` |
| Android | `LocaleListCompat.getDefault()` / system locale | `DataStore` |

> **Implementation gap (web).** `detectLocale()` in `index.ts` currently checks `localStorage`
> then returns `'en'` — it **does not consult `navigator.language(s)`**, so a Chinese browser is
> *not* auto-switched today. The required behaviour is step 2 above: after the stored check, map
> the first matching `navigator.languages` entry (`zh*` → `zh`, `de*` → `de`) before defaulting
> to English, then `loadLocale()` + `setLocale()` on first paint. Tracked as **plan S4**.

Matching is **prefix-based on the primary subtag** (normalise to lowercase, split on `-`); all
`zh-*` variants resolve to the single `zh` bundle (Simplified). Region-specific Traditional
Chinese (`zh-Hant`/`zh-TW`) is out of scope here and noted as a future bundle.

### 11.3 CJK typography

Noto Sans SC is bundled as the CJK typeface. It is the **primary** Han font — not a
"fallback" in the degraded sense. The `font-family` stack is `"Inter", "Noto Sans SC", …`
so Latin glyphs render in Inter and Han glyphs render in Noto Sans SC automatically, in the
same text run. This is how every modern Chinese-localised app works.

**CJK size calibration.** Noto Sans SC Han glyphs are visually denser than Inter Latin glyphs
at the same px size — they have higher stroke density and less internal whitespace. To make
mixed-language text read as one coherent run:

| Token | Latin-only size | Mixed / CJK-dominant size | Rationale |
|---|---|---|---|
| `--text-body` | 14px / 22px lh | 14px / **24px** lh | CJK needs +2px line-height for equivalent breathing room |
| `--text-small` | 12px / 18px lh | 12px / **20px** lh | CJK small text is the legibility floor — never go below 12px for Han |
| `--text-h3` | 18px / 26px lh | 18px / **28px** lh | Headers with mixed Latin/CJK benefit from extra line-height |
| `--text-display` / `--text-h1` / `--text-h2` | unchanged | unchanged | Large sizes have enough internal space already |

Apply via CSS: `html[lang|="zh"] { --lh-body: 24px; --lh-small: 20px; --lh-h3: 28px; }`.
Native: SwiftUI observes the locale and swaps the line-spacing constants; Compose does the
same via `LocalConfiguration`.

**Rules:**
- Do **not** apply `letter-spacing` to CJK runs — Han characters are designed to sit flush.
- Do **not** use faux-bold or faux-italic on CJK — Noto Sans SC has no italic variant, and
  synthetic italic looks wrong for Han. Use colour or size for emphasis instead.
- **Mixed-language runs** (e.g. "来自 alice@setjoin.com 的邮件"): Inter renders Latin glyphs
  at the higher CJK line-height without issue. The email address sits naturally in the Han
  sentence because both fonts share the same cap-height baseline at the same px size.
- **Display sizes** (56px+) may tighten line-height slightly for Han headlines, but never
  below 1.1× the font size.

**Font subsetting (practical air-gap concern).** Noto Sans SC Regular is ~10 MB for the full
CJK repertoire. For an air-gapped app, subset to the characters actually used:
- **Web:** subset via `unicode-range` in `@font-face` — the browser downloads only glyphs
  that appear on the page. Production webmail can also pre-subset to the admin UI's known
  character set (~2,000 hanzi, ~500 KB).
- **iOS / macOS:** `CTFontDescriptorCreateCopyWithVariation` with a character-set limitation,
  or use `UIFont` with the bundled subset OTF.
- **Android:** bundle a pre-subsetted OTF/WOFF2 in `res/font` — same ~500 KB for the UI
  character set. The full font is only needed if the app renders arbitrary user content
  (email bodies, document previews).

### 11.4 Language switcher (component)

A glass control surfaced in Settings and (optionally) the account/app-switcher popover: a
`.glass-popover` menu (or `.input`-styled `select`) listing `META[*].displayName`
(`English` / `Deutsch` / `中文`). Selecting an item calls `setLocale()`. Native equivalents:
SwiftUI `Picker` in a settings `Form`; Compose `DropdownMenu` in settings. The switcher reflects
the auto-detected locale on first run so users see "中文" already selected on a Chinese system.

### 11.5 Layout robustness & catalogs

- Strings vary in length by locale (German longest, Chinese densest) — components must size to
  content, never hardcode widths; verify all three locales against the §6 patterns.
- Dates / numbers / relative time always go through the `Intl`-backed helpers, never manual
  formatting, so they localise automatically (Chinese → `y年M月d日`, Monday-first weeks).
- **String catalogs are bundled per platform** (air-gap, §9): web `en.ts` / `de.ts` / `zh.ts`
  (dynamic-imported from local files — **never fetched from a server**); iOS String Catalogs
  (`zh-Hans.lproj/Localizable.strings` compiled into the binary); Android
  `res/values-zh-rCN/strings.xml` compiled into the APK. The full webmail/admin Chinese
  translation effort is `../platform/stage1-chinese-i18n.md`.
- Direction: en/de/zh are all LTR; `META.direction` + `dir()` already model RTL so a future
  Arabic/Hebrew bundle is additive (out of scope).

### 11.6 Self-served translations (air-gap requirement)

Every translation bundle is **shipped in the binary** — nothing is fetched from a CDN or
remote server at runtime. This is the same constraint as fonts and icons (§9.3).

| Platform | Translation format | Bundling mechanism |
|---|---|---|
| **Web** | TypeScript modules (`en.ts`, `de.ts`, `zh.ts`) | Dynamic-imported from local files in `src/lib/i18n/` — Vite tree-shakes unused locales. No network fetch. |
| **iOS / macOS** | `.xcstrings` String Catalog | Compiled into the app binary at build time. `Bundle.main` resolves the correct `.lproj` automatically. |
| **Android** | `strings.xml` per locale | Compiled into `resources.arsc` in the APK/AAB. `Context.getString()` resolves the correct locale automatically. |
| **Tauri desktop** | TypeScript (same as web) | The webmail webview loads locales from its bundled JS — same mechanism as web. |

**Adding a new locale** means adding one new file per platform (e.g. `fr.ts` + `fr.lproj/` +
`values-fr/`) and registering it in the locale metadata array. The detection rule (§11.2)
applies automatically — any new locale's primary subtag (`fr`, `ja`, `ar`) maps to the
correct bundle. No server-side change is needed — the translation lives entirely on the
client.

### 11.4 Language switcher (component)

A glass control surfaced in Settings and (optionally) the account/app-switcher popover: a
`.glass-popover` menu (or `.input`-styled `select`) listing `META[*].displayName`
(`English` / `Deutsch` / `中文`). Selecting an item calls `setLocale()`. Native equivalents:
SwiftUI `Picker` in a settings `Form`; Compose `DropdownMenu` in settings. The switcher reflects
the auto-detected locale on first run so users see "中文" already selected on a Chinese system.

### 11.5 Layout robustness & catalogs

- Strings vary in length by locale (German longest, Chinese densest) — components must size to
  content, never hardcode widths; verify all three locales against the §6 patterns.
- Dates / numbers / relative time always go through the `Intl`-backed helpers, never manual
  formatting, so they localise automatically (Chinese → `y年M月d日`, Monday-first weeks).
- **String catalogs are bundled per platform** (air-gap, §9): web `en.ts` / `de.ts` / `zh.ts`
  (dynamic-imported); iOS String Catalogs (`zh-Hans`); Android `res/values-zh-rCN`. The full
  webmail/admin Chinese translation effort is `../platform/stage1-chinese-i18n.md`.
- Direction: en/de/zh are all LTR; `META.direction` + `dir()` already model RTL so a future
  Arabic/Hebrew bundle is additive (out of scope).

---

## 12. Platform implementation references

Every design decision in this spec maps to a concrete platform API. This section is the
canonical index of "how to build what we designed" — one row per dependency, all verified
against current docs (2026-06-02). Use this before implementing any native UI.

### 12.1 Web (Svelte 5 + Vite)

| Concept | § | API | Source |
|---|---|---|---|
| Reactive state | §6-7 | `$state()`, `$derived()`, `$effect()` runes — no legacy `onMount`/`onDestroy` in runes mode | [Svelte 5](https://svelte.dev/docs/svelte) |
| CSS glass surfaces | §4.1 | `backdrop-filter: blur()` + `background: var(--glass-*-bg)` | `tokens.css` |
| Reduce transparency | §8.1 | `@media (prefers-reduced-transparency)` → swap glass to opaque `--surface-*` | [MDN](https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-transparency) |
| Reduce motion | §8.1 | `@media (prefers-reduced-motion)` → `animation: none; transition: none` | [MDN](https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion) |
| System dark mode | §3 | `@media (prefers-color-scheme: dark)` on `:root:not(.light)` | [MDN](https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-color-scheme) |
| Locale detection | §11.2 | `navigator.languages[0]`, lowercase, split on `-`, match primary subtag | [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/languages) |
| Dynamic locale load | §11.5 | `import('./zh.ts')` — Vite tree-shakes unused locales | [Vite](https://vitejs.dev/guide/features.html#dynamic-import) |
| Bundled fonts | §9.3 | `@font-face { src: url('/fonts/inter-*.woff2') }` — local paths, no CDN | `tokens.css` |

### 12.2 SwiftUI (iOS 26+ / iPadOS 26+ / macOS Tahoe+)

| Concept | § | API | Source |
|---|---|---|---|
| Glass surfaces | §4.1, §5 | `.glassEffect(.regular, in:)` (iOS 26). Back-deploy: `Material.regular`. Opacity ladder → `.ultraThin`/`.thin`/`.regular`/`.thick`/`.ultraThick` | [SwiftUI Glass](https://developer.apple.com/documentation/swiftui/glass), [Material](https://developer.apple.com/documentation/swiftui/material) |
| Aurora canvas | §4.3 | `MeshGradient` (iOS 18/macOS 15) or layered `RadialGradient` ZStack for back-deploy | [SwiftUI Gradient](https://developer.apple.com/documentation/swiftui/meshgradient) |
| Dark mode | §4.8 | `@Environment(\.colorScheme)` — asset catalog supplies Any/Dark automatically | [ColorScheme](https://developer.apple.com/documentation/swiftui/colorscheme) |
| Dynamic Type | §4.5, §8 | `.font(.custom("Inter", size: 14, relativeTo: .body))` — size scales with user preference | [SwiftUI Font](https://developer.apple.com/documentation/swiftui/font) |
| Reduce motion | §8.1 | `@Environment(\.accessibilityReduceMotion)` — drop spring, snap | [accessibilityReduceMotion](https://developer.apple.com/documentation/swiftui/environmentvalues/accessibilityreducemotion) |
| Reduce transparency | §8.1 | `@Environment(\.accessibilityReduceTransparency)` — materials auto-fallback; check with `Label("…").glassEffect(.clear).background(.black.opacity(0.3))` pattern | [EnvironmentValues](https://developer.apple.com/documentation/swiftui/environmentvalues) |
| SF Symbols | §9.1 | `Image(systemName:)` — auto weight-matches to text, Dynamic Type scaling. Render modes: monochrome, hierarchical, palette | [SF Symbols](https://developer.apple.com/design/human-interface-guidelines/sf-symbols) |
| Semantic colors | §9.2 | `.foregroundStyle(.primary)`, `.tint(.blue)`, `Color(.systemBackground)` — never hardcode hex | [Apple HIG Color](https://developer.apple.com/design/human-interface-guidelines/color) |
| Context menu | §6.2 | `.contextMenu { Button("Reply") { } … }` on any View | [SwiftUI ContextMenu](https://developer.apple.com/documentation/swiftui/view/contextmenu%28menuitems:%29) |
| Navigation (phone) | §7 | `TabView` with `.tint(module.accent)` | [TabView](https://developer.apple.com/documentation/swiftui/tabview) |
| Navigation (tablet/Mac) | §7 | `NavigationSplitView` with `.glassPane()` sidebar | [NavigationSplitView](https://developer.apple.com/documentation/swiftui/navigationsplitview) |
| Bundled fonts | §9.3 | Register in `Info.plist` (`UIAppFonts`), use via `.custom("Inter", size:)` | [Apple Custom Fonts](https://developer.apple.com/documentation/uikit/text_display_and_fonts/adding_a_custom_font_to_your_app) |
| Translation bundles | §11.6 | `.xcstrings` String Catalog — compiled into binary, `Bundle.main` resolves `.lproj` | [String Catalogs](https://developer.apple.com/documentation/xcode/localizing-and-varying-text-with-a-string-catalog) |

### 12.3 Jetpack Compose (Android)

| Concept | § | API | Source |
|---|---|---|---|
| Theme | §4 | `MaterialTheme(colorScheme = …, typography = …, shapes = …)` | [Material 3 Compose](https://developer.android.com/develop/ui/compose/designsystems/material3) |
| Glass (synthetic) | §4.1, §5 | **Haze** (`dev.chrisbanes.haze:haze`) — `hazeEffect {}` + `HazeStyle(blurRadius, tint)`. Fallback: `Modifier.blur()` via `RenderEffect` (API 31+). Solid `--surface-*` for API < 31 / battery saver | [Haze](https://chrisbanes.github.io/haze/) |
| Dynamic color | §4.4 | `dynamicLightColorScheme()` / `dynamicDarkColorScheme()` — Android 12+ | [Dynamic Color](https://developer.android.com/develop/ui/compose/designsystems/material3) |
| Dark mode | §4.8 | `isSystemInDarkTheme()` + manual toggle state | [Compose Theming](https://developer.android.com/develop/ui/compose/theming) |
| Typography | §4.5 | `Typography` with `FontFamily(Font(R.font.inter_regular))` — `sp` scales with user pref | [Compose Typography](https://developer.android.com/develop/ui/compose/text) |
| Reduce motion | §8.1 | Check `Settings.Global.ANIMATOR_DURATION_SCALE` → `snap()` instead of `tween()` | [Accessibility](https://developer.android.com/develop/ui/compose/accessibility) |
| Accessibility | §8 | `Modifier.semantics { contentDescription = "…" }` for TalkBack. `semantics` tree auto-populated for Material components | [Compose Semantics](https://developer.android.com/develop/ui/compose/semantics) |
| Icons | §9.1 | Material Symbols — bundled in APK (included with OS on Android 12+). Lucide for gaps | [Material Icons](https://m3.material.io/styles/icons/overview) |
| Context menu | §6.2 | `DropdownMenu` on long-press; `Modifier.combinedClickable(onLongClick = …)` | [Compose Menu](https://developer.android.com/develop/ui/compose/components/menu) |
| Navigation (phone) | §7 | `NavigationBar` + `ModalNavigationDrawer` | [Navigation](https://developer.android.com/develop/ui/compose/navigation) |
| Bundled fonts | §9.3 | `res/font/inter_regular.otf` → `FontFamily(Font(R.font.inter_regular))` | [Compose Fonts](https://developer.android.com/develop/ui/compose/text/fonts) |
| Translation | §11.6 | `res/values-zh-rCN/strings.xml` — compiled into `resources.arsc` | [Localization](https://developer.android.com/guide/topics/resources/localization) |

### 12.4 Tauri 2 (Desktop)

| Concept | § | API | Source |
|---|---|---|---|
| Transparent window | §5 | `tauri.conf.json`: `"transparent": true`, `"windowEffects": { "effects": ["mica"] }` | [Tauri Config](https://v2.tauri.app/reference/config/) |
| macOS titlebar | §5 | `WebviewWindowBuilder::new().title_bar_style(TitleBarStyle::Transparent)` | [Window Customization](https://v2.tauri.app/learn/window-customization/) |
| Windows Mica/Acrylic | §5 | `windowEffects` config (above). JS API: `getCurrentWindow().setEffects({ effects: ["mica"] })` | [Window API](https://v2.tauri.app/reference/javascript/api/namespacewebviewwindow/) |
| Custom titlebar controls | §5 | JS: `getCurrentWindow().minimize()` / `.toggleMaximize()` / `.close()` | [Window API](https://v2.tauri.app/reference/javascript/api/namespacewindow/) |
| Decorations toggle | §5 | `"decorations": false` in `tauri.conf.json` for fully custom titlebar | [Window Customization](https://v2.tauri.app/learn/window-customization/) |
| Updater | Phase 12 | `tauri-plugin-updater` — checks self-hosted server, no CDN | [Updater Plugin](https://v2.tauri.app/plugin/updater/) |
| Notification | Phase 12 | `tauri-plugin-notification` — system notification API | [Notification Plugin](https://v2.tauri.app/plugin/notification/) |
| Webview | §5 | Renders the webmail directly — CSS `backdrop-filter`, aurora, glass all work in WKWebView/WebView2/WebKitGTK | Built-in |

### 12.5 Rust core (mail-core + guard-core — UniFFI)

| Concept | API | Source |
|---|---|---|
| Export as object | `#[derive(uniffi::Object)]` + `#[uniffi::export] impl` → heap-allocated behind `Arc<T>`, constructors `#[uniffi::constructor]` | [UniFFI](https://mozilla.github.io/uniffi-rs/) |
| Export data | `#[derive(uniffi::Record)]` — flat struct passed by value across FFI | [Records](https://mozilla.github.io/uniffi-rs/latest/types/records) |
| Export error | `#[derive(Debug, thiserror::Error, uniffi::Error)]` — `Result<T, E>` → exceptions in Kotlin/Swift | [Errors](https://mozilla.github.io/uniffi-rs/) |
| Async | `#[uniffi::export]` on async fn — foreign executor drives future; no Rust runtime needed | [Async](https://mozilla.github.io/uniffi-rs/) |
| SQLite | `rusqlite` 0.31 (bundled SQLite) — `mail-core` local cache | [rusqlite](https://docs.rs/rusqlite) |
| HTTP | `reqwest` 0.12 (rustls) — JMAP client in `mail-core` | [reqwest](https://docs.rs/reqwest) |
| TOTP | `totp-rs` 5.x — `guard-core` code generation | [totp-rs](https://docs.rs/totp-rs) |

### 12.6 Authority files (design-time references)

These files are the **canonical sources** — code reads these, not this appendix:

| File | Role |
|---|---|
| `mailserver/webmail/src/lib/theme/tokens.css` | Single numeric source for all colours, radii, blur, motion, aurora |
| `clients/previews/webmail-preview.html` | Reference webmail mockup (16 screens, canonical glass patterns) |
| `clients/previews/desktop-preview.html` | Reference desktop mockup (Tauri transparent frame) |
| `clients/previews/mobile-preview.html` | Reference mobile mockup (iOS + Android phone frames) |
| `docs/plans/desktop-native-chrome.md` | Tauri window frame implementation plan |
| `docs/plans/apple-native-ui.md` | SwiftUI token library + component implementation plan |
| `mailserver/webmail/src/lib/i18n/index.ts` | Locale detection, `t()`, `setLocale()`, ICU fallback |
| `docs/design/platform/stage1-chinese-i18n.md` | Full Chinese translation spec |
