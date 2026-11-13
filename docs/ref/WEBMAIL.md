# Webmail Frontend — Feature Reference

The webmail is a SvelteKit 2.x SPA with Svelte 5 Runes, TypeScript, and Quill for rich-text editing. It communicates with the gateway via JMAP over HTTPS and WebSocket.

---

## Authentication & Layout

### macOS 26 Warm Grey Theme
- Warm grey palette throughout (`--gray-100` through `--gray-1000`)
- Login card with subtle shadow and rounded corners
- Dark mode support via `prefers-color-scheme`

### Auth Refresh Race Condition Fix
- `authInitializing` store tracks async `checkAuth()` state
- Root layout shows a loading spinner while auth state is being resolved
- Redirects to `/` only after auth initialization completes
- Prevents flicker/redirect loops on page refresh for authenticated users

### M365-Style App Launcher (`/apps`)
- Grid of app tiles: Mail, Calendar, Contacts, Tasks, Settings, Admin
- Tiles are conditionally shown based on user permissions (`isAdmin`, `hasMailbox`)
- Clicking a tile navigates to the corresponding app

### Collapsible Sidebar
- 220px expanded / 60px collapsed width
- Conditional nav: hides app-specific nav items when on the Apps page
- Mobile hamburger menu with overlay backdrop
- Admin nav section appears only for `isAdmin` users

---

## Mail — Inbox

### Threaded + Flat Views
- Toggle between flat message list and threaded conversation view
- Threads group by `threadId`; expand/collapse individual threads
- Mute/unmute threads (persisted in localStorage)

### Tag System (Gmail-Style Labels)
- All Mail sidebar item: shows messages excluding Trash/Spam
- Tag badges on email detail view with color support
- Archive removes location-group tags (message stays in All Mail)
- Snooze button with date/time picker

### Search
- Full-text search via JMAP `Email/query` with `text` filter
- Searches `body_tsv`, `subject_tsv`, `from_tsv` (GIN-indexed on backend)

### Message Actions
| Action | Behavior |
|---|---|
| Reply | Opens compose with recipient pre-filled; quotes original |
| Forward | Opens compose with `Fwd:` subject; includes original preview |
| Flag | Toggles `$flagged` keyword (★ / ☆) |
| Archive | Removes all location tags → appears in All Mail only |
| Snooze | Moves to Snoozed tag with wake-up timestamp |
| Delete | **First click:** moves to Trash. **In Trash:** soft-deletes |
| Edit Draft | Opens existing draft in ComposeModal for editing |

### Reading Pane
- HTML mode with sandboxed iframe (`sandbox=""`)
- Inline images replaced with blob URLs (`/blobs/{sha256}`)
- Script and event handler stripping for safety

---

## Compose Modal (Gmail-Style Floating Popup)

### Window Management
- Draggable header (click and drag to reposition)
- Resizable bottom-right corner handle
- Minimize / Maximize / Close buttons
- Position and size persisted per session

### Rich Text Editor
- Quill.js snow theme
- Toolbar: bold, italic, underline, strike, blockquote, code-block, headers, lists, links

### Outlook-Style Features
| Feature | UI | Backend Support |
|---|---|---|
| Cc / Bcc | Expandable fields | `cc_addrs`, `bcc_addrs` columns + headers |
| Reply-To | Separate field | `reply_to` column + `Reply-To` header |
| Priority | High / Normal / Low | `priority` column + `X-Priority` / `Importance` headers |
| Sensitivity | Normal / Personal / Private / Confidential | `sensitivity` column + `Sensitivity` header |
| Read Receipt | Checkbox | `read_receipt_requested` column + `Disposition-Notification-To` header |
| Voting Buttons | Up to 5 options | `vote_options` column |
| Attachments | File picker + blob upload | SeaweedFS storage with SHA-256 dedup |
| GAL Contact Picker | Search-as-you-type against LDAP GAL | `ContactCard/galSearch` JMAP method |
| Scheduled Send | Date/time picker | `scheduled_at` column + `process_scheduled_messages()` pg_cron |
| Signature | Auto-inserted below body | `signatures` table (V007) |
| Categories | Free-text labels | `categories TEXT[]` column |

### Draft Handling
- Auto-save every 5 seconds while typing
- **New draft:** creates via `Email/set Create`
- **Edit existing draft:** loads via `emailGet`, updates via destroy+create atomically
- Send: creates outgoing email + `EmailSubmission/set`, destroys old draft

---

## Recover Deleted Items (`/recover`)

Exchange OWA-style recovery page for soft-deleted emails.

- **List view:** Subject, From, Deleted At, Auto-purge countdown
- **Recover:** Restores selected emails to Inbox (bulk action supported)
- **Purge:** Permanently deletes selected emails with confirmation dialog
- **Auto-purge countdown:** Shows days remaining before automatic permanent deletion
- **Bulk actions:** Select all / Recover Selected / Purge Selected

---

## Calendar (`/calendar`)

- Month / Week / Day / Agenda views
- Event creation/edit modal with attendees, recurrence, all-day
- Event detail with RSVP buttons (Accept / Tentative / Decline)
- Calendar sidebar with visibility toggle per calendar
- Drag-to-create on time grid
- iTIP/iMIP meeting request support

---

## Contacts (`/contacts`)

- List and grid views
- vCard import/export
- Photo upload
- Department/OU grouping
- GAL browse via LDAP-backed global address list
- Merge duplicates

---

## Tasks (`/tasks`)

- Kanban + list views
- Drag-and-drop between status columns
- Assign to users
- Link to emails and calendar events
- Due dates, reminders, priority, recurrence

---

## Settings (`/settings`)

- Smart Mute toggle
- Rule templates viewer

---

## Offline Support

- IndexedDB offline queue for mutations (archive, delete, flag, send)
- Auto-replay when connection restored
- Offline status indicator badge
- WebSocket exponential backoff reconnect: 1s → 2s → 4s → 8s → max 60s

---

## Push Notifications

- WebSocket `/jmap/ws` with auto-reconnect
- Real-time inbox updates driven by PostgreSQL LISTEN/NOTIFY
- Clients detect state drift and fetch missed changes

---

## Admin Console (`/admin/*`)

### Retention Settings (`/admin/retention`)
- Log retention: Message Trace days, Mailbox Audit Log days
- **Deleted Items purge interval:** configurable auto-purge days (default 30, 0 = disabled)
- Run Prune Now button for immediate cleanup

### Other Admin Pages
- Dashboard, Users, Mailboxes, Domains, Departments, Rules, Reports, Trace, Queue, Storage, Alerts, Quarantine, DMARC, DNS, Identity

### Monitoring Dashboard (`/admin`)
- **Health checks:** Already existed — OK/Warning/Error counts + per-check status table
- **Live stats bar** (Wave 15): 24h received/sent volume, goroutines, RBL blocks, auth failures — refreshed on-demand or via 30s auto-refresh toggle
- **Auto-refresh toggle:** Default OFF, tab-session only, no persistence

### DMARC Monitor (`/admin/dmarc`)
- **Stats cards:** Pass (green), Fail (red), None (gray), TempError (yellow) — current day counts
- **Per-domain table:** Domain, pass/fail counts, policy badge (none/quarantine/reject)
- **30-day trend:** Stacked bar chart (pass/fail/none per day)
- **Recent failures:** Last 100 DMARC failures with timestamp, from address, SPF/DKIM/DMARC results
- **Auto-refresh toggle:** 30s auto-refresh option for live stats

### Quarantine (`/admin/quarantine`)
- **Virus quarantine management:** Lists all virus-infected messages across all users
- **Status filter:** Active, Released, Rejected
- **Search:** by sender or subject
- **Preview modal:** Sandboxed iframe with sanitized HTML (scripts/iframes stripped)
- **Release:** Moves message from quarantine to user's Inbox
- **Reject:** Permanently deletes the message
- **Stats bar:** Active/released/rejected counts

### User Quarantine Self-Service (`/quarantine`)
- **Inbox badge:** "Quarantined (N)" link shown in sidebar when N > 0
- **Self-service table:** Users see only their own quarantined messages
- **Preview, Release, Reject:** Same actions as admin, scoped to own messages
- **Empty state:** "Your quarantine is empty. Good news — no suspicious messages have been detected."
- **Safety:** Release confirmation dialog warns: "Only release messages you recognize and trust"

---

## File Locations

| Feature | Key Files |
|---|---|
| Auth & Theme | `webmail/src/lib/stores/auth.ts`, `webmail/src/app.css` |
| App Launcher | `webmail/src/routes/apps/+page.svelte` |
| Layout & Sidebar | `webmail/src/routes/+layout.svelte` |
| Inbox | `webmail/src/routes/inbox/+page.svelte` |
| Compose Modal | `webmail/src/lib/components/ComposeModal.svelte` |
| Compose Store | `webmail/src/lib/stores/compose.ts` |
| Recover Deleted | `webmail/src/routes/recover/+page.svelte` |
| Calendar | `webmail/src/routes/calendar/+page.svelte` |
| Contacts | `webmail/src/routes/contacts/+page.svelte` |
| Tasks | `webmail/src/routes/tasks/+page.svelte` |
| JMAP Client | `webmail/src/lib/jmap/client.ts` |
| Types | `webmail/src/lib/types/jmap.ts` |
| Admin Client | `webmail/src/lib/admin/client.ts` |
| Quarantine Admin | `webmail/src/routes/admin/quarantine/+page.svelte` |
| Quarantine User | `webmail/src/routes/quarantine/+page.svelte` |
| DMARC Monitor | `webmail/src/routes/admin/dmarc/+page.svelte` |
| Admin Monitor | `gateway/internal/handlers/admin_monitor.go` |
| MTA-STS Engine | `gateway/internal/smtp/mtasts.go` |
| TLS-RPT Worker | `gateway/internal/smtp/tlsrpt.go` |
| DANE Resolver | `gateway/internal/smtp/dane.go` |
