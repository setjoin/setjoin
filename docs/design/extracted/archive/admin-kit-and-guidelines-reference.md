# setjoin Admin Kit & Guidelines — Engineering Reference

> **Purpose.** This document is the durable, self-contained replacement for the design bundle at
> `docs/design/setjoin-design-system/` (which will be deleted). It captures, with exact values,
> everything in `ui_kits/admin/` (AdminShell.jsx, AdminScreens.jsx, AdminSecurity.jsx,
> AdminAssist.jsx, adminData.js, index.html), all 15 guideline specimens, the readme's
> CONTENT FUNDAMENTALS / VISUAL FOUNDATIONS / ICONOGRAPHY sections, `_ds_manifest.json`,
> and the shared CSS/JS the admin kit depends on (`ui_kits/shared/responsive.css`,
> `ui_kits/shared/AppRail.jsx`, `ui_kits/shared/prefs.js`, `tokens/*.css`).
>
> The React `.jsx` sources were reference renderings only — the contract is the tokens + the
> exact CSS values quoted here, re-expressed in SvelteKit. Component bundle namespace was
> `window.SetjoinDesignSystem_42c967` (components: Button, IconButton, Avatar, Badge, Card,
> Tag + TAG_COLORS, Dialog, Toast, Checkbox, Input, Select, Switch, SidebarItem, Tabs).

---

## 1. Token foundation (verbatim values)

All admin-kit CSS references these tokens. They are framework-neutral and were meant to be
copied verbatim (`styles.css` `@import`ed `tokens/fonts.css`, `colors.css`, `typography.css`,
`spacing.css`, `base.css` — load order matters only in that colors must precede usage).

### 1.1 Typography (`tokens/typography.css`)

```css
--font-sans: "IBM Plex Sans", -apple-system, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Helvetica Neue", sans-serif;
--font-mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, "PingFang SC", "Microsoft YaHei", monospace;
```

| Token | px | Use |
|---|---|---|
| `--text-2xs` | 11px | uppercase section labels (with `--tracking-caps`), table headers, micro-meta |
| `--text-xs` | 12px | meta — timestamps, counts, captions |
| `--text-sm` | 13px | secondary text, table cells, descriptions |
| `--text-md` | 14px | **UI base** — list rows, forms, menus |
| `--text-lg` | 16px | reading-pane body, small headings |
| `--text-xl` | 20px | — |
| `--text-2xl` | 24px | page-level headings |
| `--text-3xl` | 32px | — |
| `--text-display` | 44px | hero/display |

Line heights: `--leading-tight: 1.2`, `--leading-snug: 1.35`, `--leading-normal: 1.5`,
`--leading-relaxed: 1.65`.
Weights: `--weight-regular: 400`, `--weight-medium: 500`, `--weight-semibold: 600`, `--weight-bold: 700`.
Tracking: `--tracking-display: -0.02em` (≥24px headings), `--tracking-heading: -0.01em`
(16–24px headings), `--tracking-normal: 0`, `--tracking-caps: 0.06em` (uppercase labels, 11–12px).

No serif anywhere. Headings are weight 600 with −1…−2% tracking.

### 1.2 Color — light theme (`tokens/colors.css` `:root`)

**Neutral scale (cool-cast gray):**

| Token | Hex | | Token | Hex |
|---|---|---|---|---|
| `--gray-0` | `#FFFFFF` | | `--gray-500` | `#7E8395` |
| `--gray-25` | `#FBFBFD` | | `--gray-600` | `#5D6172` |
| `--gray-50` | `#F6F7F9` | | `--gray-700` | `#454857` |
| `--gray-100` | `#EFF0F4` | | `--gray-800` | `#2F3240` |
| `--gray-200` | `#E3E5EB` | | `--gray-900` | `#1E202B` |
| `--gray-300` | `#D0D3DC` | | `--gray-950` | `#14151D` |
| `--gray-400` | `#A8ACBA` | | | |

**Indigo scale (brand accent):**

| Token | Hex | | Token | Hex |
|---|---|---|---|---|
| `--indigo-50` | `#EEF0FE` | | `--indigo-600` | `#4A50D0` ← brand accent |
| `--indigo-100` | `#E1E4FD` | | `--indigo-700` | `#3E42AE` |
| `--indigo-200` | `#C9CEFA` | | `--indigo-800` | `#34378D` |
| `--indigo-300` | `#A8AFF4` | | `--indigo-900` | `#2D3071` |
| `--indigo-400` | `#828BEC` | | `--indigo-950` | `#1A1C45` |
| `--indigo-500` | `#5F66E0` | | | |

**Semantic status (fg / bg / solid triplets):**

| Status | `-fg` | `-bg` | `-solid` |
|---|---|---|---|
| success | `#1C7A36` | `#E5F4E8` | `#2B9C4C` |
| warning | `#95620C` | `#FBF1DC` | `#D29B1D` |
| danger | `#C03A30` | `#FCEBEA` | `#D4453B` |
| info | `#1D5BB8` | `#E8F0FC` | `#3B7DE0` |

**Tag palette (8 hues; subtle bg + strong fg + dot):**

| Hue | `-bg` | `-fg` | `-dot` |
|---|---|---|---|
| blue | `#E8F0FC` | `#1D5BB8` | `#3B7DE0` |
| teal | `#E2F4F3` | `#0E6B66` | `#15938C` |
| green | `#E5F4E8` | `#1C7A36` | `#2B9C4C` |
| amber | `#FBF1DC` | `#8A6510` | `#D29B1D` |
| orange | `#FCEEE4` | `#A14E14` | `#DD7833` |
| rose | `#FBEAEE` | `#B02A4C` | `#DE5277` |
| purple | `#F2ECFB` | `#6D3BB8` | `#9263DB` |
| gray | `#EFF0F4` | `#5D6172` | `#A8ACBA` |

**Semantic aliases (light):**

```css
--surface-page: var(--gray-50);     --surface-card: var(--gray-0);
--surface-sunken: var(--gray-100);  --surface-raised: var(--gray-0);
--surface-sidebar: var(--gray-25);  --surface-hover: var(--gray-100);
--surface-selected: var(--indigo-50); --surface-inverse: var(--gray-900);

--text-primary: var(--gray-900);    --text-secondary: var(--gray-600);
--text-tertiary: var(--gray-500);   --text-disabled: var(--gray-400);
--text-inverse: var(--gray-0);      --text-accent: var(--indigo-600);

--border-subtle: var(--gray-100);   --border-default: var(--gray-200);
--border-strong: var(--gray-300);   --border-accent: var(--indigo-300);

--accent: var(--indigo-600);        --accent-hover: var(--indigo-700);
--accent-active: var(--indigo-800); --accent-subtle: var(--indigo-50);
--accent-subtle-hover: var(--indigo-100); --accent-fg-on-subtle: var(--indigo-700);

--focus-ring: 0 0 0 2px var(--gray-0), 0 0 0 4px var(--indigo-300);
```

**Per-app accents (workspace launcher / app icons only — never elsewhere):**

```css
--app-mail: var(--indigo-600);  /* #4A50D0 */
--app-calendar: #3B7DE0;
--app-contacts: #2B9C4C;
--app-tasks: #DD7833;
--app-drive: #15938C;
--app-chat: #9263DB;
--app-meeting: #DE5277;
--app-auth: #D29B1D;
--app-admin: var(--gray-700);   /* #454857 */
```

### 1.3 Color — dark theme (full `[data-theme="dark"]` block, verbatim)

Toggle via `<html data-theme="dark">`. Components inherit it for free because they only
reference tokens. Authored as a flipped neutral scale + dark beds for status/tag hues.

```css
[data-theme="dark"] {
  /* Flipped neutral scale */
  --gray-0: #1B1D28;  --gray-25: #1A1C25;  --gray-50: #16171F;
  --gray-100: #262934; --gray-200: #303442; --gray-300: #3D4150;
  --gray-400: #565B6C; --gray-500: #7E8395; --gray-600: #9BA0B0;
  --gray-700: #B6BAC7; --gray-800: #D3D5DE; --gray-900: #ECEDF2;
  --gray-950: #F6F7FA;

  /* Status — darkened beds, lifted foregrounds */
  --success-fg: #6FC987;  --success-bg: #15301C;  --success-solid: #2B9C4C;
  --warning-fg: #E0B25C;  --warning-bg: #332912;  --warning-solid: #D29B1D;
  --danger-fg: #F08B83;   --danger-bg: #3A1A17;   --danger-solid: #D4453B;
  --info-fg: #7FAEF0;     --info-bg: #1A2A45;     --info-solid: #3B7DE0;

  /* Tag palette (dots unchanged except gray) */
  --tag-blue-bg: #1A2A45;   --tag-blue-fg: #7FAEF0;
  --tag-teal-bg: #12302E;   --tag-teal-fg: #5BC4BD;
  --tag-green-bg: #15301C;  --tag-green-fg: #6FC987;
  --tag-amber-bg: #332912;  --tag-amber-fg: #E0B25C;
  --tag-orange-bg: #362113; --tag-orange-fg: #E89A66;
  --tag-rose-bg: #381722;   --tag-rose-fg: #EE8FA9;
  --tag-purple-bg: #2A1F3D; --tag-purple-fg: #BD9BEA;
  --tag-gray-bg: #262934;   --tag-gray-fg: #9BA0B0;  --tag-gray-dot: #565B6C;

  /* Surfaces */
  --surface-page: #131420;   --surface-card: #1B1D28;
  --surface-sunken: #14151D; --surface-raised: #1F212D;
  --surface-sidebar: #181A24; --surface-hover: #262934;
  --surface-selected: #252849; --surface-inverse: #2F3240;

  /* Text */
  --text-primary: #ECEDF2;  --text-secondary: #9BA0B0;
  --text-tertiary: #7E8395; --text-disabled: #565B6C;
  --text-inverse: #FFFFFF;  --text-accent: var(--indigo-300);

  /* Borders */
  --border-subtle: #232531;  --border-default: #2D3040;
  --border-strong: #3D4150;  --border-accent: var(--indigo-700);

  /* Accent */
  --accent: var(--indigo-500);       --accent-hover: var(--indigo-400);
  --accent-active: var(--indigo-300); --accent-subtle: #232649;
  --accent-subtle-hover: #2A2E55;     --accent-fg-on-subtle: var(--indigo-300);

  /* Shadows — heavier on dark */
  --shadow-xs: 0 1px 2px rgba(0, 0, 0, 0.35);
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.45), 0 1px 2px rgba(0, 0, 0, 0.3);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.5), 0 1px 3px rgba(0, 0, 0, 0.35);
  --shadow-lg: 0 12px 32px rgba(0, 0, 0, 0.6), 0 2px 6px rgba(0, 0, 0, 0.4);

  --focus-ring: 0 0 0 2px var(--gray-0), 0 0 0 4px var(--indigo-700);
}
```

### 1.4 Spacing, radii, shadows, motion, layout constants (`tokens/spacing.css`)

**Spacing — 4px base grid:**
`--space-1: 4px`, `--space-2: 8px`, `--space-3: 12px`, `--space-4: 16px`, `--space-5: 20px`,
`--space-6: 24px`, `--space-8: 32px`, `--space-10: 40px`, `--space-12: 48px`, `--space-16: 64px`.

**Radii — sharp-leaning:**

| Token | px | Used for |
|---|---|---|
| `--radius-xs` | 3px | checkboxes, tiny chips |
| `--radius-sm` | 4px | buttons, inputs, tags |
| `--radius-md` | 6px | cards, menus, list selection |
| `--radius-lg` | 10px | dialogs, large panels |
| `--radius-full` | 999px | avatars, pills, dots |

**Shadows (light theme) — border-first design; shadows stay quiet:**

```css
--shadow-xs: 0 1px 2px rgba(20, 21, 29, 0.05);                                   /* cards */
--shadow-sm: 0 1px 3px rgba(20, 21, 29, 0.07), 0 1px 2px rgba(20, 21, 29, 0.04); /* raised rows */
--shadow-md: 0 4px 12px rgba(20, 21, 29, 0.09), 0 1px 3px rgba(20, 21, 29, 0.05);/* menus · popovers */
--shadow-lg: 0 12px 32px rgba(20, 21, 29, 0.14), 0 2px 6px rgba(20, 21, 29, 0.06);/* dialogs */
```

**Motion:**

```css
--ease-out: cubic-bezier(0.2, 0, 0, 1);  /* the ONLY easing curve */
--duration-fast: 120ms;
--duration-base: 180ms;
--duration-slow: 260ms;
```

Dialogs fade+drop 8px; toasts rise 8px; hovers transition background/color only.
Nothing bounces, nothing loops; honors `prefers-reduced-motion`.

**Layout constants:**

```css
--row-height: 36px;       /* list rows (mail, files, tables) */
--control-height: 32px;   /* default buttons, inputs */
--control-height-sm: 26px;
--control-height-lg: 40px; /* hero forms */
--sidebar-width: 232px;    /* mail sidebar (admin sidebar is 200px, see §2) */
--topbar-height: 52px;
```

---

## 2. Admin shell (`AdminShell.jsx` + shared layout CSS)

### 2.1 Overall frame

```
┌──────┬───────────────────────────────────────────────────────┐
│ App  │ Topbar (52px): burger(<768) · console title · role    │
│ rail │ badge · spacer · "host · version" mono · Assist btn   │
│ 56px ├──────────────┬───────────────────────────┬────────────┤
│      │ Console      │ Main (scroll, clamp pad)  │ Assist     │
│      │ sidebar      │   content max-width 980px │ drawer     │
│      │ 200px ≥768   │                           │ 320/360px  │
└──────┴──────────────┴───────────────────────────┴────────────┘
```

Root: `height: 100vh; display: flex; overflow: hidden`. Right column:
`flex: 1; display: flex; flexDirection: column; overflow: hidden; background: var(--surface-page)`.

### 2.2 App rail (shared `AppRail.jsx`, `.sj-rail`)

- `width: 56px; flex: none; flex-direction: column; align-items: center; gap: 4px; padding: 10px 0; background: var(--surface-card); border-right: 1px solid var(--border-default)`.
- Hidden below 768px (`.sj-rail { display: none; } @media (min-width: 768px){ display: flex; }`).
- Top: logo-mark img 26×26, `margin-bottom: 8px` (class `sj-ink`).
- Rail buttons: **38×38px**, `border-radius: var(--radius-sm)`, icon 18px;
  `background: active ? var(--surface-selected) : hover ? var(--surface-hover) : transparent`;
  `color: active ? var(--accent-fg-on-subtle) : var(--text-secondary)`;
  `transition: background var(--duration-fast) var(--ease-out), color var(--duration-fast) var(--ease-out)`.
- User apps: Mail `Inbox`, Calendar `Calendar`, Contacts `Users`, Tasks `SquareCheck`.
- **Admin divider**: `width: 24px; height: 1px; background: var(--border-default); margin: 8px 0 4px` —
  rendered only when `isAdmin` (RBAC: super_admin / user_admin / auditor).
- Admin console icons (admin-only): Mail admin `ServerCog`, Logs & threats `ScrollText`,
  Auth admin `ShieldCheck`.
- Bottom (after `flex: 1` spacer): theme toggle (`Sun`/`Moon`), `Settings` gear, then avatar
  button (Avatar size "md") with tooltip `"{email} — sign out"` that signs out.

### 2.3 Console switching

Three consoles, switched from the rail (ids are `admin-*`; deep-linkable via URL hash —
`index.html` reads `window.location.hash` and accepts `admin-mail | admin-logs | admin-auth`,
default `admin-mail`):

| Console id | EN | 中文 | Nav items (id · EN · 中文 · lucide icon) |
|---|---|---|---|
| `admin-mail` | Mail admin | 邮件后台 | `dashboard` System health 系统状态 `Activity` · `queue` Queue 邮件队列 `ListOrdered` · `features` Features 功能开关 `ToggleLeft` · `domains` Domains & DNS 域名与 DNS `Globe` *(stub)* · `quarantine` Quarantine 隔离区 `ShieldAlert` *(stub)* · `retention` Retention 保留策略 `Archive` *(stub)* |
| `admin-logs` | Logs & threats | 日志与威胁 | `threats` Threat flows 威胁流量 `ShieldAlert` · `audit` Audit log 审计日志 `FileSearch` · `alerts` Alerts 告警 `BellRing` |
| `admin-auth` | Auth admin | 认证后台 | `users` Users 用户 `Users` · `access` Conditional access 条件访问 `ShieldCheck` *(stub)* · `sessions` Sessions & devices 会话与设备 `MonitorSmartphone` *(stub)* |

Switching consoles resets the page to the console's first nav item and writes
`window.location.hash = id`. Navigating to a non-admin rail app sets
`localStorage["sj-app"] = id`, `localStorage["sj-mail-kit-screen"] = "workspace"` and jumps to
the mail kit; sign-out sets `sj-mail-kit-screen = "login"`.

Screen registry (implemented screens only):
`{ dashboard: AdDashboard, users: AdUsers, queue: AdQueue, audit: AdAudit, features: AdFeatures, threats: AdThreats, alerts: AdAlerts }`.
Anything else renders the stub.

**Stub screen** (`SJAdminStub`): centered column, `gap: 8; padding: "80px 0"; color: var(--text-tertiary)`;
`Construction` icon at 28px; line 1 (`--text-sm`): `"{label} — not recreated in this UI kit"` /
`"{label} — 本 UI kit 未复刻"`; line 2 (`--text-xs`): `"Exists in the real admin portal;
intentionally left blank here."` / `"真实后台中已存在；此处有意留白。"`.

### 2.4 Topbar

`height: var(--topbar-height)` (52px), `flex: none; display: flex; align-items: center; gap: 10px;
padding: 0 12px; border-bottom: 1px solid var(--border-default); background: var(--surface-card)`.

Left → right:
1. **Burger** (mobile only, `.sj-burger-md` — hidden `!important` ≥768px): a `.sj-drawer-row`
   styled `width: 44; minHeight: 44; justify-content: center; padding: 0; flex: none`,
   `Menu` icon 18px, `aria-label` "Menu"/"菜单". Opens the nav drawer.
2. Console title: `font-size: var(--text-md); font-weight: 600; white-space: nowrap`.
3. Role badge: `<Badge variant="accent">{admin.role}</Badge>` (shows `super_admin`).
4. Spacer `flex: 1`.
5. Host/version stamp (hidden <640px via `.sj-hide-sm`):
   `font-size: var(--text-xs); font-family: var(--font-mono); color: var(--text-tertiary); white-space: nowrap`
   — literal text **`mail.foundryworks.com · setjoin 3.2.1`**.
6. **Assist toggle**: `Button size="sm"`, `variant={assistOpen ? "primary" : "secondary"}`,
   icon `Sparkles` 13px, label "Assist" / "AI 助手".

### 2.5 Console sidebar

`<nav class="sj-admin-sidebar">` with inline
`background: var(--surface-sidebar); border-right: 1px solid var(--border-default); padding: 10px 8px`.
Responsive CSS: hidden below 768px; `@media (min-width: 768px) { display: block; width: 200px; flex: none; overflow-y: auto; }`.
Items are the shared `SidebarItem` component with 16px lucide icons.

### 2.6 Main content area

`<main class="sj-admin-main">`: `flex: 1; min-width: 0; overflow-y: auto; padding: clamp(14px, 3vw, 28px)`.
Content wrapper: `<div style="max-width: 980px">` — **admin content column maxes at 980px**.
Page titles use `.sj-page-title { font-size: clamp(20px, 16px + 1.2vw, 24px); }`.

### 2.7 Mobile nav drawer (shared `.sj-drawer`)

- Backdrop: `position: fixed; inset: 0; background: rgba(20, 21, 29, 0.45); z-index: 900`.
- Panel: `position: fixed; top/left/bottom: 0; width: min(304px, 85vw); background: var(--surface-card);
  border-right: 1px solid var(--border-default); z-index: 901; overflow-y: auto; padding: 12px 10px;
  animation: sjDrawerIn var(--duration-base) var(--ease-out)` where
  `@keyframes sjDrawerIn { from { transform: translateX(-16px); opacity: 0; } to { transform: none; opacity: 1; } }`
  (disabled under `prefers-reduced-motion: reduce`).
- Rows `.sj-drawer-row`: `min-height: 44px; padding: 0 10px; gap: 12px; border-radius: var(--radius-sm);
  font-size: var(--text-md); font-weight: 500`; hover/active `var(--surface-hover)`;
  `.is-active { background: var(--surface-selected); color: var(--accent-fg-on-subtle); }`.
- Divider `.sj-drawer-divider { height: 1px; background: var(--border-default); margin: 8px 0; }`.
- Drawer content: uppercase console label
  (`--text-2xs`, `--tracking-caps`, uppercase, `--text-tertiary`, weight 600, `padding: 4px 10px 6px`),
  console nav rows, divider, then `SJGlobalNavRows` (apps + admin consoles + theme + settings +
  sign out + mono email footer `padding: 10px 10px 0`).

### 2.8 Toast

Single shell-level toast: `Toast fixed message actionLabel onAction onDismiss` — every screen
gets `onToast(message, actionLabel)`; the action button simply dismisses in the kit (undo
pattern is UX contract, see §8).

### 2.9 Responsive contract (from readme + responsive.css)

Breakpoints **640 / 768 / 1024** with fluid behavior between:
- <768: no rail; hamburger drawer nav (44×44 rows); Assist is a full-screen sheet.
- 768–1023: rail + admin sidebar appear; Assist becomes a 320px side panel.
- ≥1024: full layout; (≥1280: Assist 360px).
- Stat cards: `auto-fit/minmax(170px)` grid. Admin tables scroll inside their card so the page
  never scrolls sideways (verified at 360/768/1024/1440). Touch targets ≥44px below 768px
  (`.sj-iconbtn--md`, `.sj-btn--md` min 44px, `.sj-btn--lg` 48px, inputs/selects/tabs/sidebar
  items min-height 44px).

---

## 3. Shared admin-table CSS (used by every admin table)

Header cell (`adTh` in AdminScreens.jsx; `secTh` in AdminSecurity.jsx is identical):

```js
{ textAlign: "left", padding: "8px 12px", fontSize: "var(--text-2xs)",
  letterSpacing: "var(--tracking-caps)", textTransform: "uppercase",
  color: "var(--text-tertiary)", fontWeight: 600,
  borderBottom: "1px solid var(--border-default)", whiteSpace: "nowrap" }
```

Body cell `adTd`:

```js
{ padding: "8px 12px", fontSize: "var(--text-sm)",
  borderBottom: "1px solid var(--border-subtle)", whiteSpace: "nowrap" }
```

(`secTd` differs only in `padding: "7px 12px"` — threat table rows are 1px tighter.)

Tables: `width: 100%; border-collapse: collapse`, wrapped in
`.sj-table-scroll { overflow-x: auto; }` with `.sj-table-scroll table { min-width: 640px; }`,
inside a `Card flush`.

**Inline code chip** (audit actions, geo codes, hosts):
`font-family: var(--font-mono); font-size: var(--text-xs)` (or `--text-2xs`);
`background: var(--surface-sunken); border: 1px solid var(--border-subtle);
border-radius: var(--radius-xs); padding: 1px 5px`.

**Page header pattern** (`AdPageHead`): flex row `align-items: flex-start; gap: 12;
margin-bottom: 16; flex-wrap: wrap`; title block `flex: "1 1 260px"; min-width: 0`;
`<h1 class="sj-page-title">` with `margin: 0; font-weight: 600; letter-spacing: var(--tracking-display)`;
description `<p>` `margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary)`;
action buttons flow to the right as extra children.

---

## 4. Mail admin console screens (`AdminScreens.jsx`)

### 4.1 System health dashboard (`AdDashboard`)

- Header: title "System" / "系统状态"; desc
  `"mail.foundryworks.com · setjoin 3.2.1 · uptime 84 days"` / `"… · 已运行 84 天"`.
- **Stat cards grid**: `.sj-cards-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 16px; }`
- **Each stat card** = `Card` (white card, 1px `--border-default`, `--radius-md`, `--shadow-xs`)
  containing:
  - Row 1: `display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px`
    — service label (`--text-sm`, weight 600, nowrap) + status `Badge` **with dot**.
  - Row 2 (detail): `font-size: var(--text-xs); color: var(--text-tertiary); font-family: var(--font-mono)`.
- Status→badge mapping: `ok → ["success", "Healthy"/"正常"]`, `warn → ["warning", "Attention"/"需关注"]`,
  `down → ["danger", "Down"/"离线"]`.
- Six health cards (fixture): SMTP `queue 3 · last delivery 38s ago`; IMAP / JMAP
  `214 active sessions`; LDAP `GAL sync 4 min ago`; Storage (warn) `mail-02 volume at 91%`;
  PostgreSQL `replication lag 0.2s`; TLS `renews 10 Sep 2026`.
- Below: **Active alerts** `Card` with `title="Active alerts"/"当前告警"`, `flush`, header action
  `Button size="sm" variant="ghost"` "Alert rules"/"告警规则". Each alert row:
  `display: flex; align-items: center; gap: 10px; padding: 10px 16px; border-bottom: 1px solid var(--border-subtle)`
  — severity Badge with dot (`warning|danger|info` map directly to badge variants, label is the
  raw severity word), text `flex: 1; --text-sm`, time right-aligned
  `--text-2xs` mono `--text-tertiary`.

### 4.2 Mail queue (`AdQueue`)

- Header: "Mail queue" / "邮件队列"; desc "Outbound deliveries and quarantine holds." /
  "出站投递与隔离扣留。" Action: `Button variant="secondary"` icon `RefreshCw` 14px,
  "Flush queue" / "刷新队列" → toast `"Queue flushed — retrying all"` / `"队列已刷新 — 正在重试全部"`.
- **Tabs** (shared `Tabs` component) with counts:
  `all` All/全部 (count = queue length, 5) · `queued` Queued/排队中 (3) · `failed` Failed/失败 (1) ·
  `held` Held/扣留 (1). Tab filters rows by `state`. Table sits in `margin-top: 14px`.
- State→badge: `queued → ["info","Queued"/"排队中"]`, `failed → ["danger","Failed"/"失败"]`,
  `held → ["warning","Held"/"扣留"]` — all rendered with dot.
- **Columns**: State · To · Subject · Age · Detail · (actions, header empty).
  - State: Badge+dot.
  - To: mono `--text-xs`.
  - Subject: default cell + `max-width: 220px; overflow: hidden; text-overflow: ellipsis`.
  - Age: mono `--text-xs`.
  - Detail: mono `--text-2xs`, `max-width: 260px` ellipsis;
    **color `var(--danger-fg)` when an error string exists, else `var(--text-tertiary)`**;
    content is `m.error || "tries: {n}"`.
  - Actions (right-aligned): `failed` rows get `Button size="sm" variant="secondary"`
    "Retry"/"重试" → toast "Retrying delivery now"/"正在重试投递"; `held` rows get
    "Release"/"放行" → toast `"Released to recipient inbox"` with **Undo** action ("撤销").
    Queued rows get no action.

### 4.3 Features (`AdFeatures`) — hot-reload toggles

- Header: "Features" / "功能开关"; desc
  `"Hot-reload toggles — changes apply in under a millisecond, no restart."` /
  `"热重载开关 — 变更在 1 毫秒内生效，无需重启。"` (no header action).
- `Card flush` of rows: `display: flex; align-items: center; gap: 12px; padding: 12px 16px;
  border-bottom: 1px solid var(--border-subtle)`. Per row:
  - Label `--text-sm` weight 500 + description `--text-xs` `--text-tertiary` in a `flex: 1` block.
  - Config key chip: `<code>` mono `--text-2xs` `--text-tertiary`, content **`feature.{id}`**.
  - `Switch` bound to local state; on change fires toast
    `` `feature.{id} ${enabled ? "enabled"/"已启用" : "disabled"/"已禁用"} — applied/已生效` ``.
- Fixture flags: `imap` "IMAP — Disable to free memory if all clients use JMAP" (on);
  `caldav` "CalDAV bridge — Apple Calendar / Thunderbird compatibility" (on);
  `carddav` "CardDAV bridge — Contact sync for native clients" (on);
  `quarantine` "Quarantine digest — Daily digest of held messages to users" (on);
  `tarpit` "SMTP tarpit — Slow suspicious connections instead of dropping" (**off**);
  `geoblock` "Geo-blocking — Refuse auth from countries in the block list" (**off**).

### 4.4 Domains & DNS, Quarantine, Retention

**Stubs only.** They exist as nav entries (`Globe`, `ShieldAlert`, `Archive` icons, `stub: true`)
and render `SJAdminStub` (§2.3). No domain rows, quarantine list, or retention UI was designed
in the kit — design these fresh, reusing the table/card patterns above. (The retention concept
does appear in fixture data: audit row `retention.run` on `tag:Newsletters` with
`0 purged (policy: unlimited)`, and Assist's disk-alert answer recommends a 90-day policy on
the Newsletters tag reclaiming ~120 GB.)

### 4.5 Users (`AdUsers`) — registered under the Auth admin console

- Header: "Users" / "用户"; desc (note the wit):
  `"7 accounts · 6 of 50 licensed seats… just kidding, no seats. It's your server."` /
  `"7 个账户 · 无席位限制 — 这是你自己的服务器。"`
  Action: `Button` icon `Plus` 15px "Add user"/"添加用户" → toast
  "New user form — full portal only"/"新建用户表单 — 仅完整后台提供".
- Filter input above table: wrapper `margin-bottom: 12px; max-width: 320px`; `Input`
  placeholder "Filter by name, email, role…"/"按姓名、邮箱、角色筛选…"; substring match over
  `name + email + role` (lowercased).
- **Columns**: User · Role · Status · MFA · Storage · Last login · (actions).
  - User: `Avatar size="sm"` + name (weight 500) over email (mono `--text-2xs` `--text-tertiary`),
    in a `gap: 8` flex row.
  - Role badge variants: `super_admin → accent`, `user_admin → info`, `auditor → warning`,
    `user → neutral` (label = raw role string).
  - Status badge (with dot): `active → ["success","Active"/"活跃"]`,
    `locked → ["danger","Locked"/"已锁定"]`, `pending → ["neutral","Pending"/"待激活"]`.
  - MFA and Storage cells: mono `--text-xs` (values like `passkey`, `totp`, `push`, `—`;
    `8.2 GB`).
  - Last login: `--text-xs` `--text-secondary` (relative times: "Now", "12 min ago", "Never").
  - Actions (right-aligned): locked users get `Button size="sm" variant="secondary"`
    "Unlock"/"解锁" → toast `"Account unlocked"` with **Undo**; everyone else gets an
    `IconButton size="sm"` `Ellipsis` 15px ("More"/"更多").
- RBAC roles in the system: `super_admin`, `user_admin`, `auditor`, `user`. Conditional access
  and Sessions & devices are stubs.

### 4.6 Audit log (`AdAudit`) — registered under the Logs & threats console

- Header: "Audit log" / "审计日志"; desc
  `"Every admin action and security event, across HTTP, IMAP, SMTP and LDAP."` /
  `"跨 HTTP、IMAP、SMTP、LDAP 的所有管理操作与安全事件。"`
  Action: `Button variant="secondary"` icon `Download` 14px "Export CSV"/"导出 CSV".
- Filter: `Input` with `mono` prop, placeholder "Filter events…"/"筛选事件…", substring over
  `actor + action + target + detail`.
- **Columns**: Time · Actor · Action · Target · Detail · Proto.
  - Time: mono `--text-xs` `--text-tertiary` (`09:41:07` style, 24h with seconds).
  - Actor: mono `--text-xs` (values: `system`, `threat-interceptor`, or email).
  - Action: **code chip** (see §3) with dotted event names: `alert.raised`, `login.success`,
    `captcha.enabled`, `ip.tarpit`, `user.create`, `login.lockout`, `retention.run`.
  - Target: mono `--text-xs` (e.g. `mail-02`, `webmail`, `auth`, an IP, an email, `tag:Newsletters`).
  - Detail: `--text-xs` `--text-secondary`, `max-width: 280px` ellipsis (e.g.
    `passkey · 10.0.4.22 · DE`, `spray_detection 185.220.0.0/16`, `41 failed auths / 90s`,
    `role=user dept=workshop`, `5 failed password attempts`, `0 purged (policy: unlimited)`).
  - Proto: mono `--text-2xs` `--text-tertiary` (`internal`, `http`, `imap`, `smtp+imap+http`).

---

## 5. Logs & threats screens (`AdminSecurity.jsx`)

### 5.1 Threat flows (`AdThreats`) — "UniFi-inspired threat-flow table"

- Header (inline, same pattern as `AdPageHead`): title "Threat flows" / "威胁流量"; desc
  `"Blocked and challenged connections across SMTP, IMAP, LDAP and HTTPS — one interceptor,
  every protocol."` / `"跨 SMTP、IMAP、LDAP、HTTPS 被拦截与被挑战的连接 — 一个拦截器，覆盖所有协议。"`
  Actions: `Button variant="secondary"` `Download` "Export CSV"/"导出 CSV"; and
  `Button variant="secondary"` `SlidersHorizontal` "Policies"/"策略" → toast
  "IP rules & geo-block policy — full portal only"/"IP 规则与地理封锁策略 — 仅完整后台提供".
- **Filter bar** (not a sidebar — a horizontal row: `display: flex; align-items: center;
  gap: 12px; margin-bottom: 12px; flex-wrap: wrap`):
  1. **Risk segmented control** (`SecSegment`): container
     `display: inline-flex; gap: 2px; background: var(--surface-sunken);
     border: 1px solid var(--border-default); border-radius: var(--radius-sm); padding: 2px`;
     each segment button `height: 24px; padding: 0 10px; border: none; font-size: var(--text-xs);
     font-weight: 500; border-radius: 3px`; selected:
     `background: var(--surface-card); color: var(--text-primary); box-shadow: var(--shadow-xs)`;
     unselected: `background: transparent; color: var(--text-tertiary)`.
     Options: All/全部 · Low/低 · Medium/中 · High/高.
  2. **Text filter**: wrapper `flex: "1 1 200px"; max-width: 280px; min-width: 160px`;
     `Input mono` placeholder "Filter by IP, host, rule…"/"按 IP、主机、规则筛选…"; substring
     over `src + dst + service + rule + country`.
  3. **Result count readout**: `--text-xs` mono `--text-tertiary`:
     `` `{filtered} / {total} · last 1h` `` ("近 1 小时").
- **Columns** (8): Time · Source · Geo · Destination · Service · Risk · Rule · Action.
  - Time: mono `--text-xs` `--text-tertiary` (`09:48:36`).
  - Source: mono `--text-xs` (IP).
  - Geo: country code in a **code chip** — mono `--text-2xs`, `background: var(--surface-sunken);
    border: 1px solid var(--border-subtle); border-radius: var(--radius-xs); padding: 1px 5px;
    color: var(--text-secondary)` (`NL`, `RO`, `US`, `CN`, `AT`, `KR`, `LT`, `DE`).
  - Destination: mono `--text-xs` `--text-secondary` (hostname).
  - Service: `--text-xs` plain (IMAP, SMTP AUTH, HTTPS, SMTP, LDAP, Telnet).
  - **Risk** (`SecRiskBars`): three 8×4px bars, `border-radius: 1px`, `gap: 2px`, `title={level}`;
    filled count = high 3 / medium 2 / low 1; fill color high `var(--danger-solid)`,
    medium `var(--warning-solid)`, low `var(--success-solid)`; unfilled `var(--gray-200)`.
  - Rule: bare `<code>` mono `--text-2xs` `--text-tertiary` (no chip background). Rule slugs:
    `spray_detection`, `auth_bruteforce`, `scanner_fingerprint`, `dnsbl_listed`, `geo_block`,
    `rate_limit`, `helo_invalid`, `protocol_probe`.
  - Action: Badge with dot — `Block → danger`, `Tarpit → warning`, `CAPTCHA → info`.
- Row cells use `secTd` (7px vertical padding — denser than other admin tables).

### 5.2 Alerts (`AdAlerts`)

- Header: "Alerts" / "告警"; desc `"Raised by monitoring and the threat interceptor.
  Webhooks: 2 configured."` / `"由监控与威胁拦截器产生。已配置 2 个 Webhook。"`
  Action: `Button variant="secondary"` "Alert rules"/"告警规则" → toast
  "Alert rules — full portal only"/"告警规则 — 仅完整后台提供".
- `Card flush` rows (same alert-row CSS as dashboard §4.1 plus `flex-wrap: wrap`):
  severity Badge+dot (`warning|danger|info`), text `flex: 1` `--text-sm`, time mono `--text-2xs`,
  plus `Button size="sm" variant="ghost"` "Acknowledge"/"确认" → toast
  `"Alert acknowledged"` with **Undo** ("撤销").

---

## 6. Assist drawer — ops copilot (`AdminAssist.jsx`)

### 6.1 Layout

`<aside class="sj-assist">`:
- Phones: `position: fixed; inset: 0; z-index: 800; display: flex; flex-direction: column;
  background: var(--surface-card); overflow: hidden` — **full-screen sheet**.
- ≥768px: `position: static; width: 320px; flex: none; border-left: 1px solid var(--border-default)`.
- ≥1280px: `width: 360px`.

Three zones:
1. **Header**: `height: 44px; flex: none; align-items: center; gap: 8px; padding: 0 12px;
   border-bottom: 1px solid var(--border-subtle)` — `Sparkles` 15px in `var(--accent)`,
   title "Assist"/"AI 助手" (`--text-sm`, 600, `flex: 1`), close `IconButton sm` with `X` 14px.
2. **Transcript**: `flex: 1; overflow-y: auto; padding: 14px; display: flex;
   flex-direction: column; gap: 14px`; auto-scrolls to bottom on new messages.
3. **Input form**: `flex: none; display: flex; gap: 6px; padding: 10px;
   border-top: 1px solid var(--border-subtle)`. Text input:
   `flex: 1; height: 32px; border: 1px solid var(--border-default);
   border-radius: var(--radius-sm); background: var(--surface-sunken);
   color: var(--text-primary); font: var(--font-sans) var(--text-sm); padding: 0 10px`;
   placeholder `"Ask about alerts, queue, threats…"` / `"询问告警、队列、威胁…"`.
   Submit: `Button size="md"` icon `Send` 14px, label "Ask"/"提问", disabled when empty or busy.

### 6.2 Empty state

Intro line (`--text-xs`, `--text-tertiary`, line-height 1.5):
> EN: "Ask about anything in the admin consoles. Runs against your server's own data — nothing leaves your hardware."
> ZH: "可询问管理后台中的任何内容。基于你服务器自身的数据运行 — 数据不会离开你的硬件。"

Followed by three **suggested-question buttons**: `text-align: left;
border: 1px solid var(--border-default); background: var(--surface-card);
border-radius: var(--radius-sm); padding: 8px 10px; font-size: var(--text-sm)`;
hover swaps background to `var(--surface-hover)`.

### 6.3 Suggested questions + canned answers (verbatim, EN)

1. **"Explain the active alerts"** (解释当前告警) →
   > Two alerts need attention:
   >
   > 1. **Disk 91% on mail-02** — the SeaweedFS volume grows ~4.1 GB/day; at this rate it's full in 44 days. The Newsletters tag has an unlimited retention policy — setting it to 90 days would reclaim roughly 120 GB. Otherwise add a volume server.
   >
   > 2. **Password spray from 185.220.0.0/16** — 41 attempts across 12 accounts in 90s. The interceptor already enabled the CAPTCHA gate and tarpitted the source. No account was compromised (all attempts failed pre-auth). Consider a temporary geo-block if it persists.
   >
   > The DMARC item is informational — 3 sources failing alignment are likely newsletter forwarders.

2. **"Why are queue deliveries failing?"** (队列为什么有投递失败？) →
   > One message is failing: to j.santos@oldmilldistrib.pt, error `450 4.2.1 mailbox temporarily unavailable`.
   >
   > This is a *temporary* (4xx) error — their server is asking us to retry, which we're doing (3 tries so far, next in ~4 min, exponential backoff). No action needed for 24h; after that the sender gets an NDR.
   >
   > The held message (`quarantine: spam score 9.4`) is a fake-invoice phish addressed to lena@ — recommend leaving it quarantined.

3. **"Summarize today's threats"** (总结今天的威胁) →
   > 12 blocked/challenged flows in the last hour, three patterns:
   >
   > • **Credential attacks (5)** — IMAP/SMTP-AUTH spray and brute force from NL/RO/LT botnet ranges. All tarpitted or CAPTCHA-gated; zero successful auths.
   > • **Scanners & probes (4)** — DNSBL-listed SMTP sources and one Telnet protocol probe. Blocked at connect.
   > • **Geo-policy hits (3)** — connections from ranges in the block list.
   >
   > Nothing reached a mailbox. Trend vs yesterday: +20%, driven by the spray — consider enabling SMTP tarpit globally (currently off in Features).

(Full Chinese twins exist for each; they mirror the EN content exactly — e.g. answer 1 ZH begins
"有两条告警需要处理：… **mail-02 磁盘 91%** — SeaweedFS 卷每天增长约 4.1 GB，按此速度 44 天后写满。…")

### 6.4 LLM system prompt (verbatim)

The free-form `ask()` builds this context for `window.SJAssist.complete(context, fallback)`:

```
You are Assist, the operations copilot inside the setjoin admin portal of
mail.foundryworks.com. Current state: disk 91% on mail-02 (grows 4.1GB/day, Newsletters
tag has unlimited retention); password spray from 185.220.0.0/16 CAPTCHA-gated; queue has
1 failed delivery (450 4.2.1 to oldmilldistrib.pt, retrying) and 1 quarantined phish
(spam score 9.4); 12 threat flows blocked last hour. Answer the admin's question concisely
and concretely. Style: plain prose and • bullets only — no markdown headings, no emoji,
no tables. {Answer in English. | 用中文回答。}

Question: {question}
```

**Fallback** when no canned answer and no LLM available:
> EN: "I can help with the things on this screen — alerts, the mail queue, threat flows, audit events, users and feature flags. Try one of the quick questions above, or ask about a specific IP, user, or error code."
> ZH: "我可以协助处理本界面相关的内容 — 告警、邮件队列、威胁流量、审计事件、用户与功能开关。可以试试上方的快捷提问，或询问某个具体 IP、用户或错误码。"

### 6.5 Message rendering & behavior

- Message row: `display: flex; gap: 8px; align-items: flex-start`. Avatar chip 22×22px,
  `border-radius: var(--radius-sm)`, `margin-top: 1px`; user = `User` icon 12px on
  `var(--gray-200)` / `var(--text-secondary)`; assistant = `Sparkles` 12px on
  `var(--accent-subtle)` / `var(--accent-fg-on-subtle)`.
- Body: `flex: 1; font-size: var(--text-sm); line-height: 1.55; white-space: pre-wrap;
  overflow-wrap: break-word`.
- Assistant text passes through a **minimal rich renderer** (`asRich`): splits on
  `/(\*\*[^*]+\*\*|`[^`]+`)/g`; `**bold**` → `<strong>`; `` `code` `` → inline code chip
  (mono `--text-xs`, `background: var(--surface-sunken)`, 1px `--border-subtle`,
  `border-radius: 3px`, `padding: 0 4px`). Nothing else — no headings, lists, links, tables.
- While streaming, the pending assistant bubble shows `"…"` and updates per chunk
  (`window.SJAssist.stream`). Input is locked (`busy`) until the stream completes.
- **No voice input** exists. "Voice" in the bundle refers to the *voice rule* (style contract):
  plain prose and • bullets only, no markdown headings, no emoji, no tables.
- Product decision (readme): ship Compose assist + this ops copilot behind **`feature.assist`,
  default OFF**; backend undecided — design a provider interface so local models or external
  APIs can plug in; the mock (`ui_kits/shared/assist.js`, which used `window.claude.complete`
  with deterministic canned fallbacks) defines the **UX contract only**.

---

## 7. Fixture data shapes (`adminData.js`, fictional org "Foundry Works")

Preserve these shapes — they are the de-facto view models the screens were designed around.

```js
admin:   { name, email, role }                       // "Lena Fischer", "lena@foundryworks.com", "super_admin"
health:  [{ id, label, status: "ok"|"warn"|"down", detail }]   // detail is mono micro-copy
alerts:  [{ id, severity: "warning"|"danger"|"info", time, text }] // time "09:38" or "Yesterday"
users:   [{ id, name, email, role: "super_admin"|"user_admin"|"auditor"|"user",
            status: "active"|"locked"|"pending", mfa: "passkey"|"totp"|"push"|"—",
            storage: "8.2 GB", lastLogin: "Now"|"12 min ago"|"Never" }]
queue:   [{ id, state: "queued"|"failed"|"held", to, subject, age: "12s"|"18m"|"2h",
            tries: 0|3, error?: "450 4.2.1 mailbox temporarily unavailable"
                              | "quarantine: spam score 9.4" }]
audit:   [{ id, time: "09:41:07", actor: "system"|"threat-interceptor"|email,
            action: "alert.raised"|"login.success"|"captcha.enabled"|"ip.tarpit"
                   |"user.create"|"login.lockout"|"retention.run",
            target, detail, proto: "internal"|"http"|"imap"|"smtp+imap+http" }]
features:[{ id, label, desc, on }]                   // config key rendered as feature.{id}
threats: [{ id, time: "09:48:36", src: ip, country: "NL", dst: hostname,
            service: "IMAP"|"SMTP AUTH"|"HTTPS"|"SMTP"|"LDAP"|"Telnet",
            risk: "low"|"medium"|"high",
            rule: "spray_detection"|"auth_bruteforce"|"scanner_fingerprint"|"dnsbl_listed"
                 |"geo_block"|"rate_limit"|"helo_invalid"|"protocol_probe",
            action: "Block"|"Tarpit"|"CAPTCHA" }]
```

Notable fixture content worth keeping for demos/tests: the coherent incident narrative —
disk-91% alert ↔ `alert.raised` audit row ↔ Storage warn card ↔ Assist answer; the
185.220.0.0/16 spray ↔ `captcha.enabled` + `ip.tarpit` audit rows ↔ threat rows t1/t7/t11 ↔
danger alert; the held phish "Invoice 99-2384 URGENT pay now" (spam score 9.4) ↔ Assist queue
answer. Hostnames: `mail|smtp|imap|auth.foundryworks.com`. The 12 threat rows span
NL/RO/US/CN/CN/NL/CN/AT/US/KR/LT/DE.

The kits **fake**: all data is fixture JSON; search is substring match (real = JMAP query);
auth accepts any password. Visual + interaction spec, not API spec.

---

## 8. Voice & content rules (readme CONTENT FUNDAMENTALS, condensed-verbatim)

**Voice:** plain, confident, technically literal. "Written by someone who runs the server and
trusts you to run yours." Ownership is the recurring theme.

- **Casing:** sentence case everywhere — titles, buttons, labels, nav. Uppercase only for 11px
  section labels (`TAGS`, `SYSTEM`). Product name always lowercase ("setjoin"), even at
  sentence start in brand contexts.
- **Person:** "you/your" for the user; setjoin speaks as "we" rarely, never "I". Possessives
  lean on ownership: "your hardware", "your server", "It's your server."
- **Buttons:** verb-first, specific — "Start migration", "Delete domain", "Release",
  "Flush queue" — never "OK", "Submit", "Yes".
- **Confirmation style — act-then-undo:** destructive mail actions show a toast with Undo
  ("Conversation archived — Undo") instead of asking first. Dialogs are reserved for genuinely
  irreversible admin actions, and they state consequences concretely: "This removes
  acme-corp.com and its 3 mailboxes. Mail to this domain will bounce."
- **Numbers & precision:** real units, **mono font**: "1.82 TB of 2.0 TB", "replication lag
  0.2s", "41 attempts across 12 accounts". "Precision is the brand's charisma."
- **Errors:** state the fact + the next step. "Wrong password. 2 attempts left." Never
  apologize theatrically, never "Oops".
- **Empty states:** one calm line, light wit allowed: "Nothing here. Inbox zero feels good."
  Wit is dry and infrequent — about one wink per screen, max. (Live example: the Users page
  desc, §4.5.) The only permitted decoration: logomark watermark at ~35% opacity.
- **Emoji:** never in UI. Tone markers come from typography, not pictographs.
- **Dates/times:** 24-hour clock, "10 Sep 2026", relative when recent ("12 min ago").
- **Localization:** bilingual EN/简体中文 via `SJT(en, zh)` helper; language is a user setting,
  persisted (`localStorage["sj-lang"]`, sets `<html lang>` to `zh-CN`/`en`), and **remounts the
  tree on change** (the kit used `key={prefs.lang}`). Chinese copy follows the same voice:
  plain, precise, no emoji. Font stacks include PingFang SC / Microsoft YaHei fallbacks for
  CJK. `SJT` is mock-only — production must use a real i18n library (message catalogs, not
  inline pairs); check the SvelteKit app's existing mechanism first.

**Brand idea:** setjoin reads as *set ∩ join* — set theory. Wordmark always lowercase, "set" in
ink, "join" in indigo. The logomark is two overlapping rounded squares whose intersection is
solid indigo: many tags, one message; many protocols, one engine; many apps, one platform.
Voice and visuals are "calm, precise, self-reliant — infrastructure you own."

**Visual foundations not already covered above (readme VISUAL FOUNDATIONS):**
- One accent — indigo `--indigo-600` `#4A50D0` — for primary actions, selection, links, focus.
  Status colors appear only as Badge pairs or alert tints. Tag palette is for user
  organization only — **tags never use accent indigo** (system vs user color separation).
  Per-app accents exist solely in the launcher grid.
- Backgrounds: flat solid colors only. No gradients, patterns, textures, hero imagery.
- Borders & shadows: border-first elevation. Cards = white + 1px `--gray-200` + whisper
  shadow-xs. Shadows grow only for floating layers (menu md, dialog lg). No inner shadows,
  no glows.
- Hover: background tint (`--surface-hover` gray-100), not opacity or scale. List rows reveal
  hover action clusters (small floating toolbar, bottom-right). Press: one step darker
  (`--gray-200` / `--indigo-800`). No shrink transforms.
- Selection: indigo wash `--surface-selected` + `--accent-fg-on-subtle` text; unread = 600
  weight + 7px indigo dot, never a different background.
- Focus: 2px white gap + 2px `--indigo-300` ring (`--focus-ring`), visible on every
  interactive element.
- Transparency/blur: **none**. Dialog scrim is flat `rgba(20,21,29,.45)`. No glassmorphism.
- Imagery: no photography in product UI. Avatars are initials on tag-palette hues
  (deterministic hash of the name). Marketing imagery if ever needed: neutral, cool-cast,
  hardware-adjacent — never stock "happy office people".

---

## 9. Iconography & logo rules (readme ICONOGRAPHY)

- **Icon system:** Lucide (was CDN `lucide@0.469.0`; production must vendor — tree-shaken
  imports or copied SVGs). **stroke-width 1.75**. Sizes **14–18px in controls, 24px in
  launcher tiles**. Observed in-kit sizes: 12 (assist chips), 13–15 (button icons),
  16 (sidebar), 18 (rail/burger), 28 (stub). This is a substitution flag: no in-house icon set
  exists; Lucide's 1.5–2px-stroke geometric style is the committed direction.
- **No emoji, no unicode glyph icons** (the ✕ in dismiss buttons is drawn SVG, not text).
  No filled icon style; **outline only**. Status is conveyed by **6–8px solid dots** (tag hues,
  badge dots, unread) — dots are the only "filled icon" allowed.
- **Logos:** `logo-mark.svg` (intersection mark), `logo-mark-mono.svg` (currentColor),
  `logo-wordmark.svg` (light surfaces), `logo-wordmark-dark.svg` (dark surfaces).
  **The mark may be used alone at ≥20px; the wordmark never below 100px wide.**
  Specimen sizing: wordmark 172×40 on `--surface-card` and on `--gray-950`; mark 56×56.
- **Launcher app tiles:** Lucide glyph on a **13% tint** of the app accent —
  `color-mix(in srgb, var(--app-*) 13%, white)` — **52px tile, radius-md**. (The colors-apps
  specimen rendered 44px chips with a 14% mix; readme's 13%/52px is the canonical rule.)
  Launcher app order: mail, calendar, contacts, tasks, drive, chat, meeting, auth (TOTP), admin.

---

## 10. Guidelines digest — all 15 specimens

Each specimen was a 700px-wide HTML card demonstrating canonical token usage. Their entire
informational content follows.

### Type (3)

1. **type-body.html** — "UI & reading sizes — 14px base". Demonstrates the body scale:

   | Label | Size/leading | Color | Use |
   |---|---|---|---|
   | lg 16 / 1.5 | `--text-lg` | primary | "Reading pane body — message content renders at 16px." |
   | md 14 / 1.5 | `--text-md` | primary | "Default UI text: list rows, forms, menus, settings copy." |
   | sm 13 / 1.35 | `--text-sm` | `--text-secondary` | "Secondary text — snippets, descriptions, helper copy." |
   | xs 12 / 1.35 | `--text-xs` | `--text-tertiary` | "Meta — timestamps, counts, captions." |
   | 2xs 11 caps | `--text-2xs` + `--tracking-caps` uppercase, weight 600 | `--text-tertiary` | "Section label" |

2. **type-display.html** — "IBM Plex Sans 600, tight tracking". Specimen lines:
   - `--text-display` (44px), weight 600, `--tracking-display` (−2%), `--leading-tight`:
     "Your mail. Your hardware."
   - `--text-2xl` (24px), 600, `--tracking-display`, tight: "Migration finished — 12,408 messages"
   - `--text-lg` (16px), 600, `--tracking-heading` (−1%): "Conditional access policies"
   - Caption: "display 44 · 2xl 24 · lg 16 — weight 600, tracking −2% / −1%".

3. **type-mono.html** — "IBM Plex Mono — ids, hostnames, protocol & log text".
   - Inline code chip: `background: var(--surface-sunken); border: 1px solid var(--border-subtle);
     border-radius: var(--radius-xs); padding: 1px 5px` — "inline code chips for hosts, ids, config keys"
     (specimen: `mail.acme-corp.com`).
   - **Log block**: `--text-xs` mono on `--gray-900` bed, `color: var(--gray-200);
     padding: 10px 12px; border-radius: var(--radius-md)`. Specimen line:
     `2026-06-12 09:41:07 UTC  imap  auth_ok  user=lena@acme-corp.com  ip=10.0.4.22  country=DE`.
   - Caption: "IBM Plex Mono 400/500 · log blocks on --gray-900".

### Colors (6)

4. **colors-neutral.html** — "Cool-cast neutral scale — gray 0–950". Swatch strip of all 13
   steps (0, 25, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950); values in §1.2.
   Step labels in mono; light text (`rgba(255,255,255,.85)`) on steps ≥500.

5. **colors-indigo.html** — "Brand accent scale — indigo 50–950". Swatch strip of 11 steps
   (50–950); values in §1.2; 600 is the brand accent.

6. **colors-semantic.html** — "Status colors — fg on bg pairs + solid". Four cells
   (Success/Warning/Danger/Info), each rendered as `-fg` text on `-bg` fill with a 10px `-solid`
   dot — the canonical pattern: **status text always uses the fg/bg pair; dots use solid**.
   Triplets in §1.2.

7. **colors-surfaces.html** — "Surface, text & border aliases in context". Four panels on
   `--surface-page`:
   - `--surface-card` + 1px `--border-default` + `--shadow-xs`, showing text-primary
     (semibold), text-secondary, text-tertiary stacked;
   - `--surface-sunken` + 1px `--border-subtle` — "Wells, input backgrounds";
   - `--surface-selected` + 1px `--border-accent` — "Selected row / item" in `--text-accent`
     medium;
   - `--surface-inverse` — "Tooltips, toasts" in `--text-inverse` (label at
     `rgba(255,255,255,.5)`).

8. **colors-tags.html** — "8-hue tag palette — subtle bg, strong fg, dot". **Canonical tag chip
   CSS**: `display: inline-flex; align-items: center; gap: 6px; height: 22px; padding: 0 8px;
   border-radius: var(--radius-sm); font-size: var(--text-xs); font-weight: var(--weight-medium)`
   with a **7px** round dot. Demo labels: blue Finance, teal Infra, green Approved,
   amber Pending, orange Vendors, rose Urgent, purple Personal, gray Archive. Hex in §1.2.

9. **colors-dark.html** — "Dark theme — data-theme=\"dark\" scope". Renders under
   `<html data-theme="dark">`: a `--surface-card` panel (text stack), a `--surface-selected` +
   `--border-accent` panel ("Selected row"), dark tag chips (Finance blue / Urgent rose), and a
   `--accent` panel with `--text-inverse` "Primary action". Demonstrates that components
   inherit dark for free via tokens. Full dark values in §1.3.

10. **colors-apps.html** — "Per-app accent colors for the workspace launcher". 9 launcher
    chips (mail, calendar, contacts, tasks, drive, chat, meeting, TOTP/auth, admin): 44×44
    `radius-md` chip, `background: color-mix(in srgb, var(--app-{k}) 14%, white)`, inner 16px
    `radius:4px` square in the full accent. (Readme canonical: 13% mix, 52px tile — §9.)
    Accent hex values in §1.2.

### Spacing (4)

11. **spacing-scale.html** — "4px base grid — space-1 … space-16". Bars for
    `1·4, 2·8, 3·12, 4·16, 5·20, 6·24, 8·32, 10·40, 12·48, 16·64` (token·px).

12. **radius.html** — "Sharp-leaning radii — xs 3 to lg 10, full for pills". Boxes labeled:
    **xs 3** checkbox · **sm 4** button · input · tag · **md 6** card · menu · **lg 10**
    dialog · panel · **full** avatar · dot.

13. **shadows.html** — "Quiet, border-first elevation — xs to lg". Cards labeled:
    **xs** cards · **sm** raised rows · **md** menus · popovers (with `--border-subtle`) ·
    **lg** dialogs (borderless). Exact shadow values in §1.4 (light) / §1.3 (dark).

14. **layout-constants.html** — "Fixed layout constants — control & row heights". Demos:
    **26** `--control-height-sm` · **32 — buttons, inputs** `--control-height` ·
    **36 — list rows** `--row-height` · **40 — hero forms** `--control-height-lg` ·
    **52 — topbar** `--topbar-height`.

### Brand (2)

15. **brand-logo.html** — "set ∩ join — intersection mark + lowercase wordmark". Shows the
    wordmark at 172×40 on a light card and on `--gray-950` (using `logo-wordmark-dark.svg`),
    and the mark alone at 56×56. Usage rules in §9.

16. **brand-voice.html** — "Voice — plain, confident, ownership-first". Two columns:

    **We say** (label in `--success-fg`):
    - "Your mail appears in your inbox. Zero admin tickets."
    - "Snooze until tomorrow. Schedule it for Monday morning."
    - "All data on your hardware."

    **We don't say** (label in `--danger-fg`, quotes in `--text-tertiary`):
    - "Supercharge your productivity! 🚀"
    - "Leverage seamless synergies across surfaces"
    - "Oops! Something went wrong 😅"

*(15 files; numbered 1–16 above because brand has two cards and the count includes both —
the manifest's 15 guideline cards are exactly the files in this section.)*

---

## 11. Planning notes carried over (owner decisions, 12 Jun 2026)

These were recorded in the bundle readme as overriding instructions; they remain binding for
future planning:

1. **Phase 1 scope: Mail — inbox + compose.** Admin consoles are later phases.
2. **Keep SvelteKit** — tokens + this spec are the contract; React `.jsx` files were reference
   renderings, never to be ported mechanically or imported at runtime.
3. **Vendor everything — no runtime CDN** (air-gapped deployments): self-host IBM Plex
   Sans/Mono (OFL) as woff2 + `@font-face`; vendor Lucide (ISC), stroke-width 1.75. No unpkg,
   no Google Fonts.
4. **AI assist behind `feature.assist`, default OFF**; provider interface for local models or
   external APIs; mock defines UX contract only (actions in Mail: draft / polish / translate /
   shorten; style: plain prose, no emoji, no markdown headers).
5. **Invented features are in scope** (meeting-room availability, newsletter bundles, ops
   copilot, threat-flow table) — add missing endpoints to the backend plan rather than dropping
   features.
6. **Calendar / Contacts / Tasks: no design kits — derive from Mail's patterns** (same rail +
   section sidebar + list/detail split, same tokens/metrics/responsive behavior). Don't invent
   new layouts.
7. **Component gaps to materialize as real primitives**: Table (sortable admin data table with
   `.sj-table-scroll` wrapping), Menu/Dropdown, Tooltip, Textarea, Radio, date/time picker
   (snooze + schedule send), command palette, progress/spinner, empty state, pagination — one
   file per component, token-only styling, props documented.
8. **i18n**: adopt the webmail's existing mechanism if present; otherwise a proper library with
   message catalogs. EN + 简体中文 at launch; per-user setting.
9. Theme + language persistence keys used by the kits: `sj-theme` (`light|dark` →
   `<html data-theme>`), `sj-lang` (`en|zh` → `<html lang>`), plus kit-routing keys `sj-app`
   and `sj-mail-kit-screen` (mock-only).
