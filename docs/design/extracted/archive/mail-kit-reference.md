# Mail kit reference — inbox, compose, login, settings, shared shell

> Extracted verbatim from the setjoin design-system UI-kit prototype (`ui_kits/mail/` + `ui_kits/shared/`, React 18 + lucide 0.469.0); this document fully replaces those files as the planning reference.

All `var(--*)` names refer to the setjoin design-system tokens. Two layout tokens consumed here, recorded for self-containment: `--sidebar-width: 232px`, `--topbar-height: 52px`. Icons are Lucide via the `SJIcon` wrapper (default `size = 16`, `strokeWidth = 1.75`, rendered inside `<span style="display:inline-flex; width:size; height:size; flex:none">`). Bilingual strings use `SJT(en, zh)` (see §15). Design-system components consumed by this kit: `Button`, `IconButton`, `Input`, `Select`, `Tag`, `Badge`, `Avatar`, `SidebarItem`, `Switch`, `Card`, `Checkbox`, `Toast`, `Dialog` (imported, unused).

---

## 1. App rail contract

Persistent left-edge nav on every signed-in screen (`SJAppRail`).

### Items

User apps (`RAIL_APPS`), always rendered:

| id | EN | ZH | icon |
|---|---|---|---|
| `mail` | Mail | 邮件 | `Inbox` |
| `calendar` | Calendar | 日历 | `Calendar` |
| `contacts` | Contacts | 联系人 | `Users` |
| `tasks` | Tasks | 任务 | `SquareCheck` |

Admin consoles (`RAIL_ADMIN`), rendered only when `isAdmin` (RBAC: `super_admin` / `user_admin` / `auditor`), separated from apps by a divider:

| id | EN | ZH | icon |
|---|---|---|---|
| `admin-mail` | Mail admin | 邮件后台 | `ServerCog` |
| `admin-logs` | Logs & threats | 日志与威胁 | `ScrollText` |
| `admin-auth` | Auth admin | 认证后台 | `ShieldCheck` |

Bottom cluster, in order after a `flex: 1` spacer:

1. **Theme toggle** (only if `onToggleTheme` provided) — icon `Sun` when theme is dark, `Moon` when light; label "Light mode"/"浅色模式" when dark, "Dark mode"/"深色模式" when light; never `active`.
2. **Settings** — icon `Settings`, EN "Settings" / ZH "设置", `active` when `active === "settings"`.
3. **Avatar button** — `Avatar name={user.name} size="md"`, `title` = `` `${user.email} — sign out` `` / `` `${user.email} — 退出登录` ``, `aria-label` "Sign out"/"退出登录", `onClick = onSignOut`; style `border: none; background: none; padding: 0; cursor: pointer; marginTop: 4`.

### Metrics

Rail container (`nav.sj-rail`):

```
width: 56px; flex: none; flex-direction: column; align-items: center;
gap: 4px; padding: 10px 0;
background: var(--surface-card); border-right: 1px solid var(--border-default);
```

Logo at top: `../../assets/logo-mark.svg`, class `sj-ink`, 26×26, `margin-bottom: 8px`. (`.sj-ink` images invert in dark mode: `[data-theme="dark"] img.sj-ink { filter: invert(0.92) hue-rotate(180deg); }`.)

Admin divider: `width: 24px; height: 1px; background: var(--border-default); margin: 8px 0 4px`.

### Button states (`SJRailButton`)

```
width: 38px; height: 38px; flex: none; border: none; cursor: pointer;
display: flex; align-items: center; justify-content: center;
border-radius: var(--radius-sm);
background: active ? var(--surface-selected) : hover ? var(--surface-hover) : transparent;
color:      active ? var(--accent-fg-on-subtle) : var(--text-secondary);
transition: background var(--duration-fast) var(--ease-out),
            color var(--duration-fast) var(--ease-out);
```

Icon size inside rail buttons: **18**. Each button carries `title` and `aria-label` set to the translated label (tooltip = accessibility name; there is no visible text on the rail).

### Visibility

```css
.sj-rail { display: none; }
@media (min-width: 768px) { .sj-rail { display: flex; } }
```

### Drawer mirror (`SJGlobalNavRows`)

On phones the rail is mirrored as rows inside the hamburger drawer. Structure (top to bottom): the 4 app rows → `.sj-drawer-divider` → 3 admin rows (when `isAdmin`, default `true`) → divider → theme row (same icon/label rules as rail) → Settings row → Sign out row (icon `LogOut`, "Sign out"/"退出登录") → user email footer:

```
padding: 10px 10px 0; font-size: var(--text-2xs);
font-family: var(--font-mono); color: var(--text-tertiary);
```

Rows use `SJDrawerRow` (icon size **17**, icon color `var(--accent-fg-on-subtle)` when active else `var(--text-secondary)`); row CSS in §10. Container: `display: flex; flex-direction: column; gap: 2`.

### App stub (apps without UI yet)

`SJAppStub` — centered column, `gap: 10`, `color: var(--text-tertiary)`, `background: var(--surface-page)`; logomark watermark 40×40 at `opacity: 0.35` (class `sj-ink`); line 1 (`text-sm`): `` `${label} — no UI kit yet` `` / `` `${label} — 暂无 UI kit` ``; line 2 (`text-xs`): "Exists in the product; intentionally left blank here." / "产品中已存在；此处有意留白。"

### Workspace shell wiring

- Active app persisted in `localStorage["sj-app"]`; valid values: `mail`, `settings`, `calendar`, `contacts`, `tasks`. `admin-*` ids navigate away: `window.location.href = "../admin/index.html#" + id`.
- Non-mail apps (settings/stubs) get a mobile-only workspace header `.sj-ws-header` (§10) with a 44×44 menu button, 22×22 logomark, and the app title (`text-md`, weight 600). Mail renders its own topbar and burger instead.

---

## 2. Inbox layout + metrics

### Frame

App root: `height: 100%; display: flex; flex-direction: column; background: var(--surface-card); position: relative` (the `relative` anchors the compose overlay and toast). Below the topbar: `flex: 1; display: flex; overflow: hidden` containing sidebar → list → reading pane.

### Topbar

```
height: var(--topbar-height);   /* 52px */
flex: none; display: flex; align-items: center; gap: 8px; padding: 0 10px;
border-bottom: 1px solid var(--border-default); background: var(--surface-card);
```

Contents in order:

1. Burger `IconButton` — class `sj-burger-lg` (visible below 1024px, §10), icon `Menu` size 18, label "Menu"/"菜单"; opens the drawer.
2. App title — "Mail"/"邮件": `font-size: var(--text-md); font-weight: 600; padding: 0 2px; white-space: nowrap`.
3. Search field (below).
4. `flex: 1` spacer.
5. Bell `IconButton` — icon `Bell` size 17, label "Notifications"/"通知" (inert in kit).

### Search field CSS

Wrapper: `flex: 1 1 auto; min-width: 0; max-width: 560px; position: relative; margin-left: 4px`.

Magnifier icon: `Search` size 15, `position: absolute; left: 9px; top: 8px; color: var(--text-tertiary); pointer-events: none; z-index: 1`.

Input:

```
width: 100%; height: 30px; box-sizing: border-box; padding: 0 10px 0 30px;
border-radius: var(--radius-sm); border: 1px solid var(--border-default);
background: var(--surface-sunken); color: var(--text-primary);
font-family: var(--font-sans); font-size: var(--text-sm); outline: none;
```

Focus (applied imperatively): `background → var(--surface-card)`, `border-color → var(--accent)`. Blur reverts both.

Placeholder: "Search mail — try tag:finance or from:mark" / "搜索邮件 — 试试 tag:finance 或 from:mark".

### List pane

`section.sj-mail-list`, `background: var(--surface-card)`. Widths by breakpoint:

```css
.sj-mail-list { flex: 1 1 auto; min-width: 0; width: auto; display: flex;
                flex-direction: column; overflow: hidden; border-right: none; }
@media (min-width: 768px) {
  .sj-mail-list { flex: 0 0 auto; width: clamp(280px, 40vw, 390px);
                  border-right: 1px solid var(--border-default); } }
```

List header: `display: flex; align-items: baseline; gap: 8px; padding: 12px 14px 8px; border-bottom: 1px solid var(--border-subtle)`. Title = current view/tag label (`text-md`, weight 600) + result count (`text-xs`, `font-mono`, `text-tertiary`, value = filtered list length). Scroll body: `flex: 1; overflow-y: auto`.

Header label rule: `tagFilter ? tags.find(t => t.id === tagFilter).label : SJT(viewDef.en, viewDef.zh)`.

### Reading pane

`flex: 1; min-width: 0` — takes all remaining width. Full anatomy in §6. Pane swapping on mobile in §10.

---

## 3. Sidebar model

### Views

```js
const VIEWS = [
  { id: "inbox",     en: "Inbox",     zh: "收件箱",  icon: "Inbox" },
  { id: "snoozed",   en: "Snoozed",   zh: "已暂缓",  icon: "Clock" },
  { id: "scheduled", en: "Scheduled", zh: "定时发送", icon: "CalendarClock" },
  { id: "drafts",    en: "Drafts",    zh: "草稿",    icon: "FileText" },
  { id: "sent",      en: "Sent",      zh: "已发送",  icon: "Send" },
  { id: "all",       en: "All Mail",  zh: "所有邮件", icon: "Mail" },
  { id: "trash",     en: "Trash",     zh: "回收站",  icon: "Trash2" },
];
```

(Exposed globally as `window.SJ_VIEWS`.) View icons render at size **16** in `SidebarItem`.

### Count rules

```js
const count = (v) => emails.filter((e) => e.view === v && e.unread).length;
const tagCount = (t) => emails.filter((e) => e.tags.includes(t) && e.view !== "trash").length;
```

- **Inbox** badge = unread count in inbox (`count("inbox")`).
- **Snoozed** badge = total snoozed count regardless of read state: `emails.filter((e) => e.view === "snoozed").length`.
- **All other views** = `undefined` → no badge.
- **Each tag** = count of messages carrying the tag in any view except trash.

A view row is `active` only when `view === v.id && !tagFilter` — an active tag filter visually deselects all views.

### Compose button

First item in the sidebar: `Button` with `Pencil` icon size 15, label "Compose"/"写邮件", `style={{ margin: "0 4px 12px", justifyContent: "flex-start" }}`.

### TAGS header

```
font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase;
color: var(--text-tertiary); font-weight: 600; padding: 14px 8px 4px;
display: flex; justify-content: space-between; align-items: center;
```

Label "Tags"/"标签", with a trailing `Plus` icon size 12, `cursor: pointer` (inert in kit — implies "create tag" affordance).

### Tag rows

`SidebarItem` with `dotColor={t.color}` (color dot instead of icon), `label={t.label}` (tag labels are not translated), `depth={t.depth}` (indentation for nested tags, e.g. Invoices under Finance), `count={tagCount(t.id)}`, `active={tagFilter === t.id}`, `onClick={() => onSelect("inbox", t.id)}` — clicking a tag always resets the view to `"inbox"` and sets the tag filter.

### Containers

Standalone sidebar: `className="sj-mail-sidebar"`, `background: var(--surface-sidebar); border-right: 1px solid var(--border-default); padding: 12px 8px; gap: 1`.

```css
.sj-mail-sidebar { display: none; }
@media (min-width: 1024px) {
  .sj-mail-sidebar { display: flex; flex-direction: column;
                     width: var(--sidebar-width); /* 232px */ flex: none; overflow-y: auto; } }
```

In-drawer variant (`inDrawer`): no class; `display: flex; flex-direction: column; gap: 1; width: 100%; padding: 4px 0` — same content, drawer chrome supplies background.

---

## 4. Tag filtering semantics

The exact filter from `SJMailApp` — tag filter takes precedence over the view, and trash is excluded everywhere except the Trash view itself:

```js
const list = emails.filter((e) => {
  if (tagFilter) { if (!e.tags.includes(tagFilter) || e.view === "trash") return false; }
  else if (view === "all") { if (e.view === "trash") return false; }
  else if (e.view !== view) return false;
  if (search) {
    const q = search.toLowerCase();
    if (!(e.subject + e.from + e.snippet).toLowerCase().includes(q)) return false;
  }
  return true;
});
```

Precedence, in order:

1. **Active tag filter** — show every message carrying the tag from *any* view (inbox, snoozed, scheduled, drafts, sent, all) **except trash**. The current `view` value is ignored.
2. **All Mail** — every message except trash (the "archive = remove from inbox view, keep in all" model: archiving sets `view: "all"`).
3. **Any other view** — exact `e.view === view` match.
4. **Search** — applied after view/tag filtering, as an AND (§9).

Selection wiring: `onSelect(v, t)` sets `view`, `tagFilter`, and clears `selectedId`. View clicks pass `(v.id, null)` (clearing any tag filter); tag clicks pass `("inbox", t.id)`.

---

## 5. Row anatomy (`SJMailRow`)

Three-line card per message.

Container:

```
display: flex; flex-direction: column; gap: 3px; padding: 9px 12px; cursor: pointer;
border-bottom: 1px solid var(--border-subtle); position: relative;
background: selected ? var(--surface-selected) : hover ? var(--gray-50) : transparent;
```

**Line 1** — `display: flex; align-items: center; gap: 8px`:
- Unread dot: `width: 7px; height: 7px; border-radius: 999px; flex: none; background: unread ? var(--accent) : transparent` (transparent dot keeps alignment for read rows).
- Sender: `flex: 1; font-size: var(--text-sm); font-weight: unread ? 600 : 500; color: var(--text-primary)`, single-line ellipsis (`overflow: hidden; text-overflow: ellipsis; white-space: nowrap`).
- Paperclip icon size 12, `color: var(--text-tertiary)` — only when `email.attachment`.
- Time: `font-size: var(--text-2xs); font-family: var(--font-mono); color: unread ? var(--text-accent) : var(--text-tertiary)`.

**Line 2** — subject: `padding-left: 15px` (aligns past the 7px dot + 8px gap); `font-size: var(--text-sm); font-weight: unread ? 600 : 400; color: var(--text-primary)`; single-line ellipsis.

**Line 3** — `padding-left: 15px; display: flex; align-items: center; gap: 6px`:
- Snippet: `flex: 1; font-size: var(--text-xs); color: var(--text-tertiary)`; single-line ellipsis.
- Tag chips: **first 2 tags only** (`email.tags.slice(0, 2)`), rendered as `<Tag color={tag.color} size="sm" dot={false}>{tag.label}</Tag>` — no breadcrumb in rows, no dot, small size.

**Unread treatment summary**: accent dot + sender 600 + subject 600 + accent-colored time. Read: no dot, sender 500, subject 400, tertiary time.

**Hover action cluster** — rendered only while hovered, floats over line 3:

```
position: absolute; right: 8px; bottom: 6px; display: flex; gap: 2px;
background: var(--surface-card); border: 1px solid var(--border-default);
border-radius: var(--radius-sm); box-shadow: var(--shadow-sm); padding: 2px;
```

Three `IconButton size="sm"`, all `e.stopPropagation()`:
1. Archive — `Archive` size 14, label "Archive"/"归档".
2. Star — `Star` size 14, `active={email.starred}`, label toggles "Star"/"星标" ↔ "Unstar"/"取消星标".
3. Trash — `Trash2` size 14, label "Trash"/"删除".

**Open behavior**: row click → `onOpen(id)` which selects the message **and marks it read** (`setEmailProp(id, { unread: false })`).

---

## 6. Reading pane anatomy (`SJReadingPane`)

### Toolbar

`display: flex; align-items: center; gap: 4px; padding: 10px 16px; border-bottom: 1px solid var(--border-subtle)`. Order:

1. **Back** (mobile only, when `onBack` provided) — `ArrowLeft` size 17, "Back"/"返回".
2. **Archive** — `Archive` size 16, "归档".
3. **Snooze** — `Clock` size 16, "暂缓"; wrapped in `<span style="position: relative">` so the snooze menu anchors to it; click `stopPropagation()` + toggles menu.
4. **Trash** — `Trash2` size 16, "删除".
5. **Mute** — `BellOff` size 16, "静音"; fires toast "Conversation muted — replies skip your inbox" / "会话已静音 — 后续回复将跳过收件箱" with an "Undo"/"撤销" action (no state change in kit).
6. `flex: 1` spacer.
7. **Star** — `Star` size 16, `active={email.starred}`, label toggles as in rows.

### Body container

`className="sj-reading-body"` → `padding: clamp(14px, 4vw, 28px)`; plus `flex: 1; overflow-y: auto`.

### Subject

Wrapper: `display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px`.

```
h1: font-size: clamp(17px, 1rem + 1vw, 20px); font-weight: 600;
    letter-spacing: var(--tracking-heading); margin: 0; flex: 1 1 auto;
    overflow-wrap: anywhere;
```

### Tag chips with breadcrumbs

Row: `display: flex; gap: 6px; margin-bottom: 18px; flex-wrap: wrap`. Every tag on the message renders as a removable chip:

```jsx
<Tag color={tag.color} onRemove={() => onRemoveTag(email.id, t)}>
  {tag.depth ? `${tagById(tag.parent).label}/${tag.label}` : tag.label}
</Tag>
```

Nested tags display the breadcrumb `Parent/Child` (e.g. `Finance/Invoices`) — reading pane only; rows show the bare label. After the chips, an add-tag affordance:

```
"+ tag" / "+ 标签" button:
border: 1px dashed var(--border-strong); background: none; cursor: pointer;
border-radius: var(--radius-sm); height: 22px; padding: 0 8px;
font-size: var(--text-xs); color: var(--text-tertiary);
```

In the kit it toasts "Tag picker — full client only" / "标签选择器 — 仅完整客户端提供".

### Sender block

`display: flex; align-items: center; gap: 10px; margin-bottom: 16px`:

- `Avatar name={email.from}` (default size).
- Name: `text-sm`, weight 600. Address right after it: `<{fromEmail}>` with literal angle brackets, `text-xs`, `text-tertiary`, `margin-left: 6px`, `font-mono`.
- Second line: `` {T("to me", "发送给我")} · {email.time} `` — `text-xs`, `text-tertiary`.
- Trailing `IconButton size="sm"` pair: Reply (`Reply` 15, "回复"), Forward (`Forward` 15, "转发").

### Body modes

```
white-space: pre-wrap; color: var(--text-primary); max-width: 640px;
font-size:   email.mono ? var(--text-sm)  : var(--text-lg);
font-family: email.mono ? var(--font-mono) : var(--font-sans);
line-height: email.mono ? 1.6              : var(--leading-relaxed);
```

`mono: true` is set on machine-generated mail (monitoring alerts, certbot) and renders the body as terminal-style text.

### Attachment chip

```
display: inline-flex; align-items: center; gap: 8px; margin-top: 20px; padding: 8px 12px;
border: 1px solid var(--border-default); border-radius: var(--radius-md);
background: var(--gray-25); font-size: var(--text-sm);
```

Contents: `FileText` size 16 in `var(--danger-solid)` (PDF-red affordance) → filename in `font-mono` `text-xs` → `Download` size 14 in `text-tertiary`, `cursor: pointer`.

### Inline reply

Card: `margin-top: 28px; max-width: 640px; border: 1px solid var(--border-default); border-radius: var(--radius-md); box-shadow: var(--shadow-xs)`.

Textarea:

```
width: 100%; border: none; outline: none; resize: vertical; min-height: 64px;
padding: 12px; font-family: var(--font-sans); font-size: var(--text-sm);
border-radius: var(--radius-md) var(--radius-md) 0 0; box-sizing: border-box;
```

Placeholder: `` `Reply to ${email.from}…` `` / `` `回复 ${email.from}…` ``.

Footer bar: `display: flex; justify-content: space-between; align-items: center; padding: 8px; border-top: 1px solid var(--border-subtle)`. Left group (`gap: 2`): Attach (`Paperclip` 14, "附件"), Schedule send (`CalendarClock` 14, "定时发送") — both `IconButton size="sm"`. Right: `Button size="sm"` with `Send` icon 13, label "Send"/"发送", `disabled={!reply.trim()}`; on click clears the textarea and toasts "Sending in 5s…" / "5 秒后发送…" with action "Cancel"/"取消".

### Empty state

See §16.

---

## 7. Snooze menu (`SJSnoozeMenu`)

### Presets (from fixture data, order preserved)

| EN | ZH |
|---|---|
| Later today, 18:00 | 今天 18:00 |
| Tomorrow, 8:00 | 明天 8:00 |
| This weekend, Sat 9:00 | 本周末（周六 9:00） |
| Next week, Mon 8:00 | 下周一 8:00 |

(The default for "tomorrow morning" — 8:00 — is user-configurable in Settings, §14.)

### Positioning + chrome

Anchored to the toolbar Snooze button (`position: relative` span):

```
position: absolute; top: 36px; right: 0; z-index: 50;
background: var(--surface-card); border: 1px solid var(--border-default);
border-radius: var(--radius-md); box-shadow: var(--shadow-md);
padding: 4px; width: 200px;
```

Header "Snooze until"/"暂缓至": `text-2xs`, `var(--tracking-caps)`, uppercase, `text-tertiary`, weight 600, `padding: 6px 8px 4px`.

Items — one full-width button per preset:

```
display: block; width: 100%; text-align: left; border: none; background: none;
cursor: pointer; font-family: inherit; font-size: var(--text-sm);
color: var(--text-primary); padding: 7px 8px; border-radius: var(--radius-sm);
hover: background var(--surface-hover)   (mouseenter/leave, inline)
```

### Dismissal

A document-level click listener closes the menu; the menu's own root calls `e.stopPropagation()` on click, and the toolbar toggle button also stops propagation — so any click outside the menu dismisses it, plus Escape via nothing (only outside-click; Escape is handled by the drawer, not this menu):

```js
React.useEffect(() => {
  const h = () => onClose();
  document.addEventListener("click", h);
  return () => document.removeEventListener("click", h);
}, [onClose]);
```

### Snooze action semantics (in `SJMailApp`)

```js
const onSnooze = (id, preset) => {
  const prev = emails.find((e) => e.id === id);
  const prevState = { view: prev.view, time: prev.time };
  setEmailProp(id, { view: "snoozed", time: SJTt("Snoozed", "已暂缓") + " · " + preset.split(/[,（(]/)[0] });
  if (selectedId === id) setSelectedId(null);
  showToast(SJTt("Snoozed until ", "暂缓至 ") + preset, SJTt("Undo", "撤销"), () => setEmailProp(id, prevState));
};
```

Notes: the row's time field is replaced with `"Snoozed · "` + the preset truncated at the first comma or open-paren (ASCII or full-width) — e.g. "Snoozed · Later today". Undo restores both `view` and the original `time` string. Picking a preset also deselects the open conversation.

---

## 8. Undo toast flow

Single-toast machinery in `SJMailApp` — an action ref plus a message:

```js
const showToast = (message, actionLabel, undoFn) => {
  undoRef.current = undoFn || null;
  setToast({ message, actionLabel });
};
const setEmailProp = (id, patch) => setEmails((es) => es.map((e) => (e.id === id ? { ...e, ...patch } : e)));

const moveTo = (id, dest, msg) => {
  const prev = emails.find((e) => e.id === id);
  const prevView = prev.view;
  setEmailProp(id, { view: dest });
  if (selectedId === id) setSelectedId(null);
  showToast(msg, SJTt("Undo", "撤销"), () => setEmailProp(id, { view: prevView }));
};
```

Rendering: `<Toast fixed message actionLabel onAction onDismiss>`; `onAction` runs `undoRef.current()` then clears the toast; `onDismiss` just clears.

### Action → destination → copy

| Action | Mutation | Toast EN | Toast ZH | Action label |
|---|---|---|---|---|
| Archive | `view → "all"` | Conversation archived | 会话已归档 | Undo / 撤销 |
| Trash | `view → "trash"` | Conversation moved to Trash | 会话已移至回收站 | Undo / 撤销 |
| Snooze | `view → "snoozed"`, time rewritten | Snoozed until {preset} | 暂缓至 {preset} | Undo / 撤销 |
| Remove tag | tag removed from `tags[]` | Tag removed | 已移除标签 | Undo / 撤销 |
| Mute | none (kit) | Conversation muted — replies skip your inbox | 会话已静音 — 后续回复将跳过收件箱 | Undo / 撤销 |
| Inline reply send | reply cleared | Sending in 5s… | 5 秒后发送… | Cancel / 取消 |

Tag-removal undo keeps the full prior array:

```js
const onRemoveTag = (id, tagId) => {
  const prevTags = [...emails.find((e) => e.id === id).tags];
  setEmailProp(id, { tags: prevTags.filter((t) => t !== tagId) });
  showToast(SJTt("Tag removed", "已移除标签"), SJTt("Undo", "撤销"), () => setEmailProp(id, { tags: prevTags }));
};
```

Convention: destructive/move actions get **Undo/撤销**; in-flight sends get **Cancel/取消**. Archive is "move to All Mail", consistent with §4 — archived mail stays reachable via All Mail and tag filters.

---

## 9. Search behavior

**Advertised** (placeholder): operator syntax — "Search mail — try tag:finance or from:mark" / "搜索邮件 — 试试 tag:finance 或 from:mark".

**Actually implemented** (prototype): case-insensitive substring over the concatenation of subject + sender name + snippet, applied after view/tag filtering:

```js
if (search) {
  const q = search.toLowerCase();
  if (!(e.subject + e.from + e.snippet).toLowerCase().includes(q)) return false;
}
```

Gap to honor in production: `tag:` and `from:` operators are promised by the placeholder but not parsed — a real implementation must either support them (tag: matches tag ids/labels; from: matches sender name/address) or change the placeholder. Body text and `fromEmail` are *not* searched by the prototype. Search is live (filters on every keystroke), has no clear button, no result highlighting, and does not alter the selected message.

---

## 10. Responsive behavior

Breakpoints: **640 / 768 / 1024** (plus 1280 for the admin assist panel width). Mobile-first: base styles target `<640px`; `min-width` queries enhance upward. Inline component styles deliberately omit the properties owned by `responsive.css` (display/width of responsive panes).

### Viewport hook

```js
function SJUseViewport() {
  const read = () => ({ isMobile: window.innerWidth < 768, isCompact: window.innerWidth < 1024 });
  // rAF-throttled resize listener; returns the same object identity unless a flag flipped
}
```

### Per-breakpoint behavior (mail)

| Range | Rail | Mail sidebar | Burger | Panes |
|---|---|---|---|---|
| `<768` (`isMobile`) | hidden | hidden (drawer only) | visible | **single pane**: list OR reading pane — `(!vp.isMobile || !selected)` shows the list, `(!vp.isMobile || selected)` shows the reading pane; reading pane gets an `onBack` that clears selection |
| `768–1023` (`isCompact`) | visible | hidden (drawer only) | visible | list (fixed `clamp(280px, 40vw, 390px)`, right border) + reading pane |
| `≥1024` | visible | visible, 232px | hidden | full three-pane |

Burger visibility classes (the `!important` exists because component-injected styles load later and would win ties):

```css
.sj-burger-md { display: inline-flex; }            /* admin: until sidebar appears */
@media (min-width: 768px) { .sj-burger-md { display: none !important; } }
.sj-burger-lg { display: inline-flex; }            /* mail: until its sidebar appears */
@media (min-width: 1024px) { .sj-burger-lg { display: none !important; } }
```

### Drawer CSS

```css
.sj-drawer-backdrop { position: fixed; inset: 0; background: rgba(20, 21, 29, 0.45); z-index: 900; }
.sj-drawer { position: fixed; top: 0; left: 0; bottom: 0; width: min(304px, 85vw);
             background: var(--surface-card); border-right: 1px solid var(--border-default);
             z-index: 901; overflow-y: auto; padding: 12px 10px;
             animation: sjDrawerIn var(--duration-base) var(--ease-out); }
@keyframes sjDrawerIn { from { transform: translateX(-16px); opacity: 0; } to { transform: none; opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .sj-drawer { animation: none; } }
.sj-drawer-row { display: flex; align-items: center; gap: 12px; width: 100%; min-height: 44px;
                 padding: 0 10px; border: none; background: transparent; border-radius: var(--radius-sm);
                 font-family: var(--font-sans); font-size: var(--text-md); font-weight: 500;
                 color: var(--text-primary); cursor: pointer; text-align: left; }
.sj-drawer-row:hover, .sj-drawer-row:active { background: var(--surface-hover); }
.sj-drawer-row.is-active { background: var(--surface-selected); color: var(--accent-fg-on-subtle); }
.sj-drawer-divider { height: 1px; background: var(--border-default); margin: 8px 0; }
```

Drawer behavior (`SJDrawer`): renders nothing when closed; backdrop click closes; `Escape` closes (document keydown listener active only while open); `role="dialog" aria-modal="true"`. Mail's drawer content = `SJMailSidebar inDrawer` + `.sj-drawer-divider` + `SJGlobalNavRows` (when rail props passed); every selection inside the drawer also closes it.

### Workspace mobile header (settings / stub pages only)

```css
.sj-ws-header { display: flex; align-items: center; gap: 10px; height: 48px; flex: none;
                padding: 0 8px; border-bottom: 1px solid var(--border-default);
                background: var(--surface-card); }
@media (min-width: 768px) { .sj-ws-header { display: none; } }
```

Its menu button is a `.sj-drawer-row` forced to `width: 44px; min-height: 44px; justify-content: center; padding: 0; flex: none`.

### 44px touch rules

```css
@media (max-width: 767px) {
  .sj-iconbtn--md { min-width: 44px; min-height: 44px; }
  .sj-btn--md { min-height: 44px; }
  .sj-btn--lg { min-height: 48px; }
  .sj-sbitem { min-height: 44px; }
  .sj-tab { min-height: 44px; }
  .sj-input, .sj-select { min-height: 44px; }
}
```

### Other shared responsive utilities

```css
.sj-page-title { font-size: clamp(20px, 16px + 1.2vw, 24px); }
img { max-width: 100%; height: auto; }
.sj-cq { container-type: inline-size; }
.sj-form-grid { display: grid; grid-template-columns: 1fr; gap: 14px 20px; align-items: start; }
@container (min-width: 460px) { .sj-form-grid { grid-template-columns: 1fr 1fr; } }
.sj-span-all { grid-column: 1 / -1; }
.sj-hide-sm { display: none; }
@media (min-width: 640px) { .sj-hide-sm { display: inline; } }
.sj-wrap-row { flex-wrap: wrap; }
.sj-cards-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 16px; }
.sj-table-scroll { overflow-x: auto; }
.sj-table-scroll table { min-width: 640px; }
```

---

## 11. Compose surface (`SJComposeScreen`)

### Overlay + header

Full-cover overlay inside the mail app's `position: relative` root (it covers topbar/list/reading pane but **not** the app rail): `position: absolute; inset: 0; z-index: 100; display: flex; flex-direction: column; background: var(--surface-card)`.

Header: `height: var(--topbar-height); flex: none; display: flex; align-items: center; gap: 10px; padding: 0 16px; border-bottom: 1px solid var(--border-default)` — `Pencil` 16 in `var(--accent)`, title "New message"/"新邮件" (`text-md`, 600), spacer, Close `IconButton` (`X` 16, "Close"/"关闭").

### Layout CSS (responsive.css)

```css
/* ——— Compose: stacked column → message + options side panel ——— */
.sj-compose-body { flex: 1; min-height: 0; display: flex; flex-direction: column; overflow-y: auto; }
.sj-compose-main { display: flex; flex-direction: column; padding: 8px clamp(12px, 3vw, 24px) 16px; }
.sj-compose-main textarea { min-height: 160px; }
.sj-compose-options { width: 100%; border-top: 1px solid var(--border-default); background: var(--surface-sidebar); padding: 16px 16px 24px; display: flex; flex-direction: column; gap: 20px; }
@media (min-width: 1024px) {
  .sj-compose-body { flex-direction: row; overflow: hidden; }
  .sj-compose-main { flex: 1; min-width: 0; overflow: hidden; }
  .sj-compose-main textarea { flex: 1; min-height: 0; }
  .sj-compose-options { width: 312px; flex: none; border-top: none; border-left: 1px solid var(--border-default); overflow-y: auto; }
}
```

Below 1024px the options panel stacks under the message and the whole body scrolls; at ≥1024px it becomes a fixed 312px right sidebar with its own scroll and the body textarea grows to fill.

### Field metrics

```js
const cpField = {
  display: "flex", alignItems: "center", gap: 10, minHeight: 38,
  borderBottom: "1px solid var(--border-subtle)", padding: "0 2px",
};
const cpLabel = { width: 64, flex: "none", fontSize: "var(--text-sm)", color: "var(--text-tertiary)" };
const cpInput = {
  flex: 1, border: "none", outline: "none", background: "transparent",
  fontFamily: "var(--font-sans)", fontSize: "var(--text-sm)", color: "var(--text-primary)", padding: "8px 0",
};
const cpSectionHead = {
  fontSize: "var(--text-2xs)", letterSpacing: "var(--tracking-caps)", textTransform: "uppercase",
  color: "var(--text-tertiary)", fontWeight: 600, padding: "0 0 8px",
};
```

Options-panel control style:

```js
const selStyle = { height: 28, border: "1px solid var(--border-default)", borderRadius: "var(--radius-sm)",
  background: "var(--surface-card)", color: "var(--text-primary)", fontFamily: "var(--font-sans)",
  fontSize: "var(--text-xs)", padding: "0 6px" };
```

### Message column fields (top to bottom)

1. **From** — label "From"/"发件人"; `<select>` styled `{...cpInput, cursor: "pointer", appearance: "none", fontFamily: "var(--font-mono)", fontSize: "var(--text-xs)"}`. Options (alias model: personal + alias + shared mailbox):
   - `Lena Fischer <lena@foundryworks.com>` (default, the user)
   - `Support (alias)` / `支持（别名）` `<support@foundryworks.com>`
   - `Billing (shared)` / `财务（共享）` `<billing@foundryworks.com>`
2. **To** — label "To"/"收件人"; input, `autoFocus`, placeholder `mark@foundryworks.com`. Inline at right while hidden: **Cc** and **Bcc** reveal buttons — `border: none; background: none; color: var(--text-accent); font-size: var(--text-xs)`, labels "Cc"/"抄送", "Bcc"/"密送"; each disappears once clicked and its field appears.
3. **Cc** (revealed) — placeholder `sofia@foundryworks.com`.
4. **Bcc** (revealed) — no placeholder.
5. **Subject** — label "Subject"/"主题"; `{...cpInput, fontWeight: 500}`.
6. **Body textarea** — `flex: 1; border: none; outline: none; resize: none; background: transparent; padding: 14px 2px; font-family: var(--font-sans); font-size: var(--text-md); line-height: 1.6; color: var(--text-primary)`; placeholder "Write your message…"/"输入正文…"; `min-height: 160px` when stacked.

### Send bar

`display: flex; align-items: center; gap: 8px; padding-top: 10px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap`:

- **Send** `Button` — icon `Send` 14, `disabled={!to.trim()}`; label switches with scheduling: `schedule === "now"` → "Send"/"发送", otherwise "Schedule send"/"定时发送".
- **Attach** `IconButton` (`Paperclip` 16, "附件") → toast "File picker — full client only" / "文件选择器 — 仅完整客户端提供".
- spacer.
- Hint: `text-2xs`, `text-tertiary` — "Undo window: 10s after send" / "发送后 10 秒内可撤回".
- **Discard** `IconButton` (`Trash2` 16, "Discard"/"丢弃") → closes compose without confirmation.

### Options column — Delivery

Section head "Delivery"/"发送选项". Column `gap: 10`:

- Schedule row: `<label>` flex, gap 8, `text-sm`; caption `<span style="width: 80px; color: var(--text-secondary)">` "When"/"时间"; `<select>` `{...selStyle, flex: 1}` with options `now` "Send now"/"立即发送" (default), `mon8` "Monday, 8:00"/"周一 8:00", `custom` "Custom…"/"自定义…".
- `Switch` "Read receipt"/"已读回执", default **off**.

### Options column — Meeting

Section head "Meeting"/"会议". `Switch` "Include meeting invite"/"附带会议邀请", default **off**. When on, a column (`gap: 8; margin-top: 10`):

- Date/time/duration row (`display: flex; gap: 6`):
  - `<input type="date">` `{...selStyle, flex: 1, fontFamily: "var(--font-mono)"}`, default `2026-06-26`.
  - Time `<select>` (selStyle): `9:00, 9:30, 10:00, 10:30, 14:00, 15:00`, default `10:00`.
  - Duration `<select>` (selStyle): `30 / 60 / 90` + "min"/"分钟", default `30`.
- Caption `text-2xs` `text-tertiary`: "Rooms free at that time" / "该时段会议室空闲情况".
- One `CpRoomRow` per room (fixture rooms in §17).

Room row — exact selection/disabled styling:

```jsx
const busy = room.status === "busy";
<button onClick={() => !busy && onPick(room.id)} disabled={busy} style={{
  display: "flex", alignItems: "center", gap: 8, width: "100%", textAlign: "left",
  border: "1px solid " + (selected ? "var(--border-accent)" : "var(--border-default)"),
  background: selected ? "var(--surface-selected)" : "var(--surface-card)",
  borderRadius: "var(--radius-sm)", padding: "7px 10px", cursor: busy ? "not-allowed" : "pointer",
  fontFamily: "inherit", opacity: busy ? 0.55 : 1,
}}>
```

Contents: `DoorOpen` 15 (`var(--accent-fg-on-subtle)` when selected else `text-tertiary`); name `text-sm` `text-primary`, weight 500 selected / 400 not, with capacity suffix `· {capacity} seats`/`人` in `text-tertiary` `text-xs`; trailing `Badge`: busy → `variant="warning" dot` "busy until {until}"/"占用至 {until}", free → `variant="success" dot` "free"/"空闲". Busy rooms are unselectable (disabled + guard in onClick). Single-select (`room` holds one id).

### Options column — Tag on send

Section head "Tag on send"/"发送时打标签". Chip wrap (`display: flex; flex-wrap: wrap; gap: 6`) of **top-level tags only** (`tags.filter((t) => !t.depth)`), each a clickable `Tag color size="sm"` toggling membership in `sendTags`; selection treatment is an outline, not a fill:

```jsx
style={{ outline: sendTags.includes(t.id) ? "1.5px solid var(--border-accent)" : "none" }}
```

Multi-select. (Note: `sendTags` is collected but not echoed in the send toast.)

### Options column — Assist

Last section, separated by `border-top: 1px solid var(--border-subtle); padding-top: 16px`. Full contract in §12.

### Send toast composition

```js
const send = () => {
  const parts = [];
  if (schedule !== "now") parts.push(CpT("scheduled for Monday 8:00", "已定时：周一 8:00"));
  if (meeting && room) parts.push(CpT(`room ${CP_DATA.rooms.find((r) => r.id === room).name} booked`,
                                      `已预订会议室 ${CP_DATA.rooms.find((r) => r.id === room).name}`));
  const base = schedule === "now" ? CpT("Sending in 5s…", "5 秒后发送…") : CpT("Message scheduled", "邮件已定时");
  onToast(parts.length ? `${base} · ${parts.join(" · ")}` : base,
          schedule === "now" ? CpT("Cancel", "取消") : CpT("Undo", "撤销"));
  onClose();
};
```

So: immediate send → "Sending in 5s…" with **Cancel**; scheduled → "Message scheduled · scheduled for Monday 8:00" with **Undo**; a booked room appends "· room Walnut booked"/"· 已预订会议室 Walnut". Compose closes on send.

---

## 12. Assist panel (CpAssist, inside compose options)

### Header

`cpSectionHead` with leading `Sparkles` icon size 11, `vertical-align: -1px; margin-right: 4px; color: var(--accent)`; label "Assist" / "AI 助手".

### Actions

Buttons: `Button size="sm" variant="secondary"`, icon size 13, all disabled while any action runs; wrap row `gap: 6`.

| id | EN label | ZH label | icon |
|---|---|---|---|
| `draft` | Draft it | 起草 | `PenLine` |
| `polish` | Polish | 润色 | `Wand2` |
| `translate` | Translate to 中文 *(shown in EN UI)* | 翻译成 English *(shown in ZH UI)* | `Languages` |
| `shorten` | Shorten | 精简 | `AlignVerticalSpaceAround` |

(Translate always targets the *other* language — its label is itself computed via `CpT("Translate to 中文", "翻译成 English")`.)

Hint line under the buttons: `text-2xs`, `text-tertiary`, `margin-top: 8`, `line-height: 1.5`. Idle copy: "Writes into the body. Review before sending." / "结果直接写入正文，发送前请检查。" While waiting: "Thinking…" / "思考中…".

### Prompts (verbatim)

```js
const prompts = {
  draft: `You are the writing assistant in setjoin Mail. Draft a concise, plain, professional email body (no subject line, plain text only, no markdown) for the subject: "${subject}". ${CpT("Reply in English.", "用中文回复。")}`,
  polish: `Polish this email body, keep the meaning and tone calm and plain. Reply with the body only, plain text, no markdown:\n\n${body}`,
  translate: CpT(`Translate this email body to Simplified Chinese, body only, plain text:\n\n${body || subject}`, `Translate this email body to English, body only, plain text:\n\n${body || subject}`),
  shorten: `Shorten this email body to its essentials. Body only, plain text, no markdown:\n\n${body}`,
};
```

Voice rules baked into every prompt: body only (never a subject line), plain text, no markdown, tone "concise, plain, professional" / "calm and plain". Output language follows the UI language for drafting; translate flips it.

### Runtime behavior (`window.SJAssist`)

```js
window.SJAssist = {
  async complete(prompt, fallback) {
    try {
      if (window.claude && typeof window.claude.complete === "function") {
        const r = await window.claude.complete(prompt);
        if (r && typeof r === "string") return r.trim();
      }
    } catch (e) { /* fall through to canned answer */ }
    await new Promise((res) => setTimeout(res, 700));
    return fallback;
  },
  // Typewriter: calls onChunk with the growing string, resolves when done.
  async stream(text, onChunk, step = 3, interval = 12) {
    let i = 0;
    return new Promise((res) => {
      const id = setInterval(() => {
        i = Math.min(text.length, i + step);
        onChunk(text.slice(0, i));
        if (i >= text.length) { clearInterval(id); res(); }
      }, interval);
    });
  },
};
```

- `complete`: uses a live model (`window.claude.complete`) when available and returning a string; on any error/absence it waits **700ms** (simulated latency) and returns the deterministic fallback.
- `stream`: typewriter render — grows the string by **3 chars every 12ms**, calling `onChunk` with the prefix, resolving at full length.
- Compose flow: `setBusy(true)` → hint "Thinking…" → `complete()` → clear hint → `stream(result, setBody)` (result replaces the body, character by character) → `setBusy(false)`.

### Canned fallbacks (verbatim)

```js
const fallbacks = {
  draft: CpT(
    `Hi,\n\nFollowing up on "${subject || "our discussion"}" — here is where things stand and what I need from you:\n\n• Current status: on track\n• Open question: timing\n• Next step: please confirm by Friday\n\nThanks,\nLena`,
    `你好，\n\n关于「${subject || "我们讨论的事项"}」，目前进展和需要你确认的事项如下：\n\n• 当前状态：正常推进\n• 待确认：时间安排\n• 下一步：请在周五前回复确认\n\n谢谢，\nLena`
  ),
  polish: CpT(
    (body || "").trim() ? `${body.trim()}\n\n— polished: clearer phrasing, same meaning. (Connect Claude for real rewrites.)` : "Write a few sentences first, then I can polish them.",
    (body || "").trim() ? `${body.trim()}\n\n——已润色：表达更清晰，语义不变。（接入 Claude 后可真实改写。）` : "请先写几句内容，我再帮你润色。"
  ),
  translate: CpT(
    `（中文译文）\n\n${(body || subject || "…").trim()}\n\n——以上为演示译文。接入 Claude 后将提供真实翻译。`,
    `(English translation)\n\n${(body || subject || "…").trim()}\n\n— Demo translation. Connect Claude for the real thing.`
  ),
  shorten: CpT(
    (body || "").split("\n").slice(0, 2).join("\n") || "Nothing to shorten yet.",
    (body || "").split("\n").slice(0, 2).join("\n") || "暂无可精简的内容。"
  ),
};
```

(Note the responsive.css `.sj-assist` block — full-screen sheet `<768px`, 320px side panel `≥768px`, 360px `≥1280px` — belongs to the *admin* assist panel; the mail compose assist lives inside `.sj-compose-options` and does not use it.)

---

## 13. Login screen (`SJLoginScreen`)

### Two-step machine

`step: "password" | "totp"`.

```js
const submitPassword = (e) => {
  e.preventDefault();
  if (!password) return;
  setBusy(true);
  setTimeout(() => { setBusy(false); setStep("totp"); }, 450);   // simulated check: 450ms
};
const submitCode = (e) => {
  e.preventDefault();
  if (code.replace(/\D/g, "").length < 6) return;                 // requires 6 digits
  setBusy(true);
  setTimeout(() => onSignedIn(), 400);                            // simulated verify: 400ms
};
```

### Metrics

- Page: `min-height: 100vh`, centered column, `background: var(--surface-page)`, `padding: 24px`.
- Column: `width: min(360px, 100%); display: flex; flex-direction: column; gap: 20px`.
- Wordmark above the card: theme-aware source — `logo-wordmark-dark.svg` when `document.documentElement.dataset.theme === "dark"`, else `logo-wordmark.svg`; **146×34**, self-centered.
- Card: `background: var(--surface-card); border: 1px solid var(--border-default); border-radius: var(--radius-lg); box-shadow: var(--shadow-sm); padding: 24px`. Forms inside: column, `gap: 14px`.
- Titles: `text-xl`, weight 600, `letter-spacing: -0.01em`. Subtitles: `text-sm`, `text-secondary`, `margin-top: 2px`.

### Step 1 — password

- Title "Sign in"/"登录"; subtitle "to your Foundry Works workspace"/"登录到 Foundry Works 工作区".
- `Input label="Email"/"邮箱" size="lg" type="email"` — prefilled `lena@foundryworks.com`, `autoFocus`.
- `Input label="Password"/"密码" size="lg" type="password"` — placeholder `••••••••••`.
- `Checkbox` "Remember this device for 30 days"/"30 天内记住此设备" — default **checked**, `white-space: nowrap`.
- `Button size="lg"` — `disabled={!password || busy}`; label busy ? "Checking…"/"验证中…" : "Continue"/"继续".
- Link "Forgot password?"/"忘记密码？" — `text-sm`, `var(--text-accent)`, no underline, self-centered, nowrap (inert).

### Step 2 — TOTP

- Title "Two-step verification"/"两步验证"; subtitle "Enter the 6-digit code from your authenticator app."/"输入验证器应用中的 6 位验证码。".
- Code `Input size="lg" mono autoFocus` — placeholder `000 000`, `inputMode="numeric"`, `text-align: center`; onChange sanitizer: `e.target.value.replace(/[^\d ]/g, "").slice(0, 7)` (digits + spaces only, max 7 chars so "123 456" fits).
- `Button size="lg"` — `disabled={code.replace(/\D/g, "").length < 6 || busy}`; label busy ? "Verifying…"/"验证中…" : "Sign in"/"登录".
- Text button "Use a passkey instead"/"改用 Passkey 登录" — `border: none; background: none; text-sm; var(--text-accent)` (in the kit it returns to the password step).

### Footer

Below the card — `text-xs`, `text-tertiary`, centered, `line-height: 1.5`, two lines:

```
mail.foundryworks.com · self-hosted with setjoin        / 由 setjoin 自托管
All data stays on Foundry Works hardware.               / 所有数据均保存在 Foundry Works 自有硬件上。
```

---

## 14. UserSettings (`SJUserSettings`)

Personal preferences only — server admin lives in the admin consoles, and the page says so.

### Page frame

`height: 100%; overflow-y: auto; background: var(--surface-page)`. Inner column: `max-width: 720px; margin: 0 auto; padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px; display: flex; flex-direction: column; gap: 16px`.

Header: `h1.sj-page-title` (fluid `clamp(20px, 16px + 1.2vw, 24px)`), weight 600, `letter-spacing: var(--tracking-display)` — "Settings"/"设置". Subtitle (`text-sm`, `text-secondary`, `margin: 4px 0 0`): "Your preferences. Server administration lives in the admin consoles." / "你的个人偏好。服务器管理在左侧的管理后台中。"

Local toggle defaults: `{ bundling: true, shortcuts: true, notify: false, compact: false }`. Every toggle flip and most selects fire toast "Saved"/"已保存" (fixed `Toast`).

Form layout: cards use `.sj-cq` + `.sj-form-grid` (1 column, 2 columns when the container is ≥460px; `.sj-span-all` spans both).

### Card: Profile ("Profile"/"个人资料")

- `Avatar name size="xl"` beside the form (`gap: 16`, wraps).
- `Input` "Display name"/"显示名称" — editable, initial "Lena Fischer".
- `Input` "Email"/"邮箱" — `mono`, **disabled** (address is admin-owned).
- `Button variant="secondary" size="sm"` "Save changes"/"保存修改" → toast "Profile saved"/"资料已保存".

### Card: Appearance & language ("Appearance & language"/"外观与语言")

- `Select` "Theme"/"主题" — options Light/"浅色", Dark/"深色"; value from `SJPrefs.get().theme`; onChange → `SJPrefs.setTheme(v)` + toast "Saved" + `onPrefsChange()`.
- `Select` "Language"/"语言" — options `en` "English", `zh` "中文（简体）" (labels untranslated); onChange → `SJPrefs.setLang(v)` + `onPrefsChange()` (no toast — the whole tree remounts, §15).
- `Switch` "Compact rows"/"紧凑行距", description "Tighter mail list density"/"更紧凑的邮件列表密度" — default **off**.

### Card: Mail ("Mail"/"邮件")

- `Select` "Undo send window"/"发送撤回时长" — options "5 seconds"/"5 秒", "10 seconds"/"10 秒", "30 seconds"/"30 秒"; default **10 seconds** (matches the compose hint "Undo window: 10s after send").
- `Select` "“Tomorrow morning” snooze time"/"「明天早上」暂缓时间" — options `7:00 / 8:00 / 9:00`; default **8:00** (matches snooze preset "Tomorrow, 8:00").
- `Switch` "Bundle newsletters"/"聚合订阅邮件" — desc "Group messages tagged Newsletters into a daily row"/"将带 Newsletters 标签的邮件按天聚合"; default **on** (pairs with the `bundled: true` email flag, §17).
- `Switch` "Keyboard shortcuts"/"键盘快捷键" — desc "e archive · s snooze · c compose · / search"/"e 归档 · s 暂缓 · c 写邮件 · / 搜索"; default **on**. (This is the canonical shortcut map: `e` archive, `s` snooze, `c` compose, `/` search.)
- `Switch` "Desktop notifications"/"桌面通知" — desc "Only for messages tagged Urgent"/"仅限带 Urgent 标签的邮件"; default **off**.

### Card: Security ("Security"/"安全")

Read-only enrollment rows (`text-sm`, `gap: 10`):

- `Badge variant="success" dot` **Passkey** — "Added 12 Mar 2026 ·"/"添加于 2026-03-12 ·" + device name `MacBook Pro` in `<code>` (`font-mono`, `text-xs`, `text-tertiary`).
- `Badge variant="success" dot` **TOTP** — "Authenticator app, enrolled 02 Jan 2026"/"验证器应用，注册于 2026-01-02".

Buttons (`variant="secondary" size="sm"`, wrap row, `padding-top: 4`): "Add passkey"/"添加 Passkey" → toast "Passkey enrollment — full client only"/"Passkey 注册 — 仅完整客户端提供"; "Change password"/"修改密码" → toast "Password change — full client only"/"修改密码 — 仅完整客户端提供".

---

## 15. prefs.js contract

Plain script, loaded before any React code. Exposes `window.SJPrefs` + `window.SJT`.

```js
var KEY_THEME = "sj-theme";   // "light" (default) | "dark"
var KEY_LANG  = "sj-lang";    // "en" (default) | "zh"

get()        → { theme: localStorage[KEY_THEME] || "light", lang: localStorage[KEY_LANG] || "en" }
setTheme(t)  → persists + document.documentElement.dataset.theme = t
setLang(l)   → persists + document.documentElement.lang = (l === "zh" ? "zh-CN" : "en")
init()       → applies both on load (called immediately at script eval, before first paint)

window.SJT = function (en, zh) {
  return prefs.get().lang === "zh" && zh != null ? zh : en;
};
```

Key facts:

- **Theme application** = `data-theme` attribute on `<html>` (dark tokens key off `[data-theme="dark"]`; `.sj-ink` images invert under it). The rail/drawer theme toggle calls `setTheme(theme === "dark" ? "light" : "dark")` then `onPrefsChange()`.
- **`SJT` is read at render time**, not subscribed — so language changes require a **remount**: the kit root sets `key={prefs.lang}` on the top-level component ("key={prefs.lang} remounts the tree so every SJT() label re-evaluates on language change") and `onPrefsChange` is just a tick: `setTick((t) => t + 1)`.
- `SJT` falls back to EN when `zh` is null/undefined.
- Additional shell localStorage keys (from the kit harness, same pattern worth keeping): `sj-app` (active workspace app: `mail | settings | calendar | contacts | tasks`) and `sj-mail-kit-screen` (`login | workspace`; unknown/absent → login).

---

## 16. Empty states + logomark watermark

Standard watermark treatment — the product logomark used as a quiet placeholder, never decorative chrome:

```jsx
<img src=".../logo-mark.svg" className="sj-ink" width="40" height="40" alt="" style={{ opacity: 0.35 }} />
```

(Always 40×40, `opacity: 0.35`, `alt=""`, `sj-ink` so it inverts in dark mode.)

Three instances:

1. **Reading pane, nothing selected** — centered column, `gap: 10`, `color: var(--text-tertiary)`: watermark + "Select a conversation"/"选择一封邮件" (`text-sm`).
2. **Empty list** — no watermark; `padding: 32px`, centered, `text-sm`, `text-tertiary`: "Nothing here. Inbox zero feels good." / "这里空空如也。清空收件箱的感觉真好。"
3. **App stub** (calendar/contacts/tasks) — centered on `var(--surface-page)`: watermark + `` `${label} — no UI kit yet` ``/`` `${label} — 暂无 UI kit` `` (`text-sm`) + "Exists in the product; intentionally left blank here."/"产品中已存在；此处有意留白。" (`text-xs`).

Voice note: empty states are calm and slightly warm ("Inbox zero feels good") — one sentence, no exclamation marks, no illustrations beyond the watermark.

---

## 17. Fixture data model worth preserving

Fictional tenant: **Foundry Works** (`foundryworks.com`); user `{ name: "Lena Fischer", email: "lena@foundryworks.com" }`; demo host `mail.foundryworks.com`.

### Tags — hue, hierarchy

```js
tags: [
  { id: "finance",     label: "Finance",     color: "blue",   depth: 0 },
  { id: "invoices",    label: "Invoices",    color: "blue",   depth: 1, parent: "finance" },
  { id: "infra",       label: "Infra",       color: "teal",   depth: 0 },
  { id: "hr",          label: "HR",          color: "green",  depth: 0 },
  { id: "vendors",     label: "Vendors",     color: "orange", depth: 0 },
  { id: "urgent",      label: "Urgent",      color: "rose",   depth: 0 },
  { id: "personal",    label: "Personal",    color: "purple", depth: 0 },
  { id: "newsletters", label: "Newsletters", color: "gray",   depth: 0 },
]
```

Model facts: `depth` (0/1) drives sidebar indentation and reading-pane breadcrumbs; children share the parent's hue (Invoices = blue like Finance); `parent` is the tag id; compose "Tag on send" offers only `depth: 0` tags; `urgent` is referenced by the desktop-notifications setting, `newsletters` by the bundling setting and the monitoring email's retention suggestion.

### Email record shape

| field | type | notes |
|---|---|---|
| `id` | string | prefix encodes origin in fixtures: `m*` inbox, `s*` snoozed, `t*` scheduled, `d*` drafts |
| `from` / `fromEmail` | string | display name + address (searched: `from` only) |
| `unread`, `starred` | bool | |
| `time` | string | display string, not a date — e.g. `"09:41"`, `"Yesterday"`, `"Tue"`, `"Snoozed · Fri 8:00"`, `"Mon 08:00"`, `"Draft"`; rewritten on snooze |
| `tags` | string[] | tag ids; rows show first 2 |
| `view` | string | one of `inbox / snoozed / scheduled / drafts / sent / all / trash` — single mutable location pointer |
| `subject`, `snippet`, `body` | string | body uses `\n`, rendered `pre-wrap` |
| `attachment` | string? | filename → paperclip in row + chip in reading pane |
| `mono` | bool? | machine-generated mail → monospace body mode |
| `bundled` | bool? | newsletter bundling flag (set on the JMAP Weekly fixture `m8`; consumed conceptually by the "Bundle newsletters" setting — no bundling UI in the kit) |

Fixture census (13 messages): 9 inbox (3 unread: monitoring alert with `urgent+infra` + `mono`, invoice with `finance+invoices` + attachment, HR onboarding), 1 starred (`m4` Q2 budget, attachment), 1 snoozed (`s1`, `time: "Snoozed · Fri 8:00"`), 1 scheduled (`t1`, `time: "Mon 08:00"`, subject "(sends Monday 08:00)"), 1 draft (`d1`, `time: "Draft"`, snippet prefixed "Draft: "). Sent and Trash start empty. Attachments are all `.pdf` (`invoice-2384.pdf`, `q2-budget-review.pdf`, `pricelist-2026-h2.pdf`).

### Rooms

```js
rooms: [
  { id: "walnut",   name: "Walnut",         capacity: 4,  status: "free" },
  { id: "birch",    name: "Birch",          capacity: 10, status: "busy", until: "11:00" },
  { id: "workshop", name: "Workshop floor", capacity: 20, status: "free" },
]
```

`status: "free" | "busy"`; `until` only on busy rooms (feeds the warning badge "busy until 11:00").

### Snooze presets

```js
snoozePresets: [
  { en: "Later today, 18:00",        zh: "今天 18:00" },
  { en: "Tomorrow, 8:00",            zh: "明天 8:00" },
  { en: "This weekend, Sat 9:00",    zh: "本周末（周六 9:00）" },
  { en: "Next week, Mon 8:00",       zh: "下周一 8:00" },
]
```

Preset strings are split at the first `,`, `（`, or `(` to produce the compact row time label (§7).
