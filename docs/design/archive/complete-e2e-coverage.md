# Complete E2E Test Coverage — Design Spec

> All user interactions cataloged from actual SvelteKit source. Organized into 6 phased domains.
> Each phase is independent: can be planned and executed separately.

## Current State

301 tests across 24 spec files. Coverage ~20% — mostly page-load smoke. Missing ~80% of detailed user interactions (form validation, edge cases, CRUD cycles, error states, modal dialogs).

---

## Phase 1: ComposeModal — Full Flow

**Critical because:** Compose is the core product function. Every email starts here.

### 1.1 — Core Send Flow
- Send with To only (success)
- Send with To + Subject (success)
- Send with To + Subject + Body (success)
- Send with empty To → client validation error
- Send with empty Subject → client validation error (required field)
- Send with Cc filled (success)
- Send with Bcc filled (success)
- Send with Reply-To set (success)
- Send with all fields filled (success)
- Double-click Send → second click blocked by `sending` guard
- Send with large body (>10KB text) (success)

### 1.2 — Advanced Fields
- Priority select: High / Normal / Low
- Sensitivity select: Normal / Personal / Private / Confidential
- Scheduled send: set future datetime → button label changes to "Schedule Send"
- Read receipt checkbox: toggle on, verify sent email has `readReceiptRequested: true`
- Voting buttons: enable, add 2 options, verify headers in sent email
- S/MIME encrypt checkbox: toggle on (if user has cert)
- Flag for follow-up checkbox

### 1.3 — From/Identity
- From dropdown shows user email (default)
- From dropdown shows delegated identities (if user has delegates)
- Select delegated identity → sends as that identity
- Send-as validation: cannot send as identity without permission → MailTips warning

### 1.4 — Attachments
- Upload single small file (success, shows in list)
- Upload multiple files (success, all shown in list)
- Upload large file (>25MB) → error handling
- Drag-and-drop file onto compose (success)
- Remove attachment from list
- Send with attachment → verify blob stored

### 1.5 — GAL Autocomplete
- Type 2+ characters in To → GAL dropdown appears
- Select contact from GAL → fills To field
- GAL search error → "Search unavailable" message
- GAL search on Cc field (independent)
- No GAL results → dropdown not shown

### 1.6 — Drafts
- Type in compose → auto-save after 5s idle
- Draft save indicator (visual cue)
- Draft save error → tap-to-retry indicator
- Manual "Save Draft" button works
- Close compose → reopen → draft content restored
- Discard draft → fields cleared, draft deleted
- Reply draft: pre-filled recipient + quoted body
- Forward draft: pre-filled subject "Fwd:", empty To
- Draft with attachment survives close/reopen

### 1.7 — MailTips
- Large audience (>25 recipients) → yellow warning badge
- External domain recipient → orange "[EXTERNAL]" badge
- Recipient on vacation → blue OOO badge
- No send-as permission → red warning

### 1.8 — Modal Behavior
- Open compose → modal visible, To field focused
- Close via × button → compose state cleared
- Close via overlay click → compose state cleared
- Close via Escape key → compose state cleared
- Drag header to move modal
- Resize bottom-right corner
- Minimize → collapse to header bar
- Maximize from minimized state
- Modal position persists after drag
- Modal size constrained (min 360×280)

### 1.9 — Signature
- Signature checkbox: toggle on → signature inserted at cursor
- Signature textarea: edit and save
- Signature persists across compose sessions
- Reply/Forward: signature placed above quoted text

### 1.10 — Categories / Tags
- Add category tag to outgoing email
- Remove category from outgoing email
- Multiple categories on one email

---

## Phase 2: Inbox — Full Flow

### 2.1 — Reading
- Click email → detail pane opens
- Detail shows: sender, recipients, subject, date, body
- Click back → returns to list
- Threaded view: click thread → expand child emails
- Collapse thread
- Flat view: all emails shown individually
- HTML email body: "Show HTML" toggle
- HTML email renders in sandboxed iframe
- Plain text email: no HTML toggle

### 2.2 — Actions
- Flag email → star icon appears
- Unflag email → star icon removed
- Archive email → removed from inbox, visible in All Mail
- Delete email → moved to Trash
- In Trash: delete permanently → gone
- In Trash: Recover → back to inbox
- Mute thread → thread hidden from inbox
- Unmute thread → thread visible again
- Bulk select: select multiple, archive all
- Bulk select: delete all selected

### 2.3 — Snooze
- Snooze "Later today" → sets snooze until preset time
- Snooze "Tomorrow morning" → sets to 9am
- Snooze "This weekend" → sets to Saturday 10am
- Snooze "Next week" → sets to Monday 9am
- Snooze custom → datetime-local picker
- After snooze time: email returns to inbox
- Snoozed tag visible in sidebar

### 2.4 — Search
- Search by sender name → filtered results
- Search by subject keyword → filtered results
- Search with no results → "No messages" empty state
- Clear search → full inbox restored
- Search with special characters → properly escaped

### 2.5 — Tags / Labels
- Assign existing tag to email → badge appears
- Remove tag from email → badge removed
- Create new tag → appears in sidebar
- Filter by tag → only tagged emails shown
- System tags: Inbox, Sent, Drafts, Trash, Spam
- Custom tags: hierarchical display

### 2.6 — Pagination
- Scroll to bottom → "Load more" button
- Click "Load more" → next 50 emails loaded
- Load more while loading → button disabled
- All emails loaded → "Load more" hidden
- Position tracking across loads

### 2.7 — Edge Cases
- Empty inbox → "No messages" state
- Offline badge shown when disconnected
- Reconnect → badge hidden, emails refresh
- Read receipt request → auto-sends on open
- Vote response email → shows vote buttons

---

## Phase 3: Calendar — Full Flow

### 3.1 — Event CRUD
- Create event with title only (success)
- Create event with all fields (title, date, time, location, description)
- Create event without title → validation error
- Create all-day event → no time fields, spans full day
- Edit event: change title, save
- Edit event: change date, save
- Edit event: change time, save
- Delete event with confirm
- Delete event without confirm (cancel)

### 3.2 — Recurrence
- Create weekly recurring event (every Tuesday)
- Create monthly recurring event (15th of each month)
- Create yearly recurring event
- Edit recurring event: "This event only" vs "All events"
- Delete recurring: "This event only" vs "All events"
- Recurrence rule displayed in detail view

### 3.3 — RSVP / Attendees
- Add attendees (comma-separated emails)
- RSVP "Accept" → status updated
- RSVP "Tentative" → status updated
- RSVP "Decline" → status updated
- RSVP button disabled while responding (`responding` guard)
- View event as attendee: RSVP buttons visible
- View event as non-attendee: RSVP buttons hidden

### 3.4 — Views
- Month view: 6-week grid with events
- Month view: "+N more" when >3 events per day
- Week view: 7-day time grid
- Day view: single day time grid
- Agenda view: upcoming events list
- Navigate next month → shows next month's events
- Navigate previous month → shows previous month's events
- Today button → returns to current date

### 3.5 — Scheduling Assistant
- Open "Find a Time" modal
- Add attendees
- Set date range + duration
- Click "Find Slots" → results appear
- Click available slot → pre-fills create modal
- No free slots → "No free slots found" state

### 3.6 — Calendar Management
- Toggle calendar visibility (checkbox)
- Hidden calendar: events not shown in grid
- Visible calendar: events shown with color dot
- Multiple calendars: color-coded events
- Delegated "Send on behalf of" dropdown

---

## Phase 4: Contacts + Tasks + Settings

### 4.1 — Contacts
- Create contact with display name only (minimal)
- Create contact with all fields (first, last, company, phone, email)
- Edit contact: change name, save
- Edit contact: add phone row, remove phone row
- Edit contact: add email row, remove email row
- Delete contact with confirm
- Cancel delete
- Photo upload (small PNG/JPG)
- Photo preview in detail view
- Initials display when no photo
- GAL search: type name, see results
- Import from GAL: contact copied to personal address book
- List view / Grid view toggle
- Search contacts by name: filtered results
- Empty state: "No contacts found"

### 4.2 — Tasks
- Create task with title only (minimal)
- Create task with all fields (priority, due, description, categories)
- Edit task: change title, save
- Edit task: change priority, save
- Delete task with confirm
- Kanban view: move task from "To Do" to "In Progress"
- Kanban view: move task from "In Progress" to "Done"
- Kanban view: move task to "Cancelled"
- List view: table with all columns
- Status filter: show only "To Do" tasks
- Status filter: show only "Done" tasks
- Search tasks: filtered results
- Overdue task: red styling
- Due date display on task card
- Categories as chips on task card
- Empty state: "No tasks found"

### 4.3 — Settings
- Display name: edit and save
- Language: change to German, verify UI updates
- Language: change to Chinese, verify UI updates
- TOTP: setup flow (generate QR → enter code → verify → enabled badge)
- TOTP: disable flow (click disable → confirm → disabled badge)
- TOTP: wrong code → error message
- App password: generate (name + label → token displayed once)
- App password: revoke (confirm → removed from list)
- Webhook: create (URL + events → secret displayed)
- Webhook: delete (confirm → removed from list)
- Smart Mute: enable → creates server rule
- Smart Mute: disable → removes server rule
- IMAP tag visibility: toggle individual tag
- IMAP tag visibility: "Expose all new tags" checkbox
- Password change: enter current + new → success
- Password change: wrong current → error
- Password change: new < 8 chars → validation error

---

## Phase 5: Admin — Full Flow

### 5.1 — Users
- Create user: valid email + password → appears in list
- Create user: duplicate email → server error displayed
- Create user: empty fields → client validation
- Edit user: change display name
- Edit user: change department
- Toggle user enabled/disabled → state persists
- Toggle admin: promote → admin role visible
- Reset password: enter new → success
- Reset password: force-change checkbox
- Add alias: valid email → appears in list
- Remove alias: disappears from list
- Set quota: enter bytes → saved
- CSV import: drag file, see results count
- CSV import: invalid file → error
- CSV import: too large (>10MB) → error
- Impersonate: click "View as User" → redirects to inbox with impersonation banner
- Exit impersonation → redirected back to admin
- Delete user: confirm → removed from list

### 5.2 — Mailboxes
- Create mailbox: select user + name → appears in list
- Edit mailbox: change name, quota
- Edit mailbox: litigation hold toggle with warning
- Edit mailbox: set purge days
- View folders: list with message counts
- Create folder: name → appears in list
- Delete folder: confirm → removed
- Import messages: upload .mbox/.eml/.zip → imported count
- Export messages: select format → trigger download

### 5.3 — Domains
- Create domain: name → appears in list
- Set primary domain: checkbox toggled
- DMARC policy: change to reject → saved
- MTA-STS: change to enforce → saved
- Delete domain: confirm with "all users and mail lost" warning

### 5.4 — DLP
- Create pattern: name + regex + severity → appears in list
- Edit pattern: change regex, save
- Delete pattern: confirm → removed
- Test pattern: paste sample text → matching patterns shown
- Test pattern: no match → "no matches" state
- Toggle pattern enabled/disabled

### 5.5 — eDiscovery
- Search by keyword → results list appears
- Search by date range → filtered results
- Search with no results → empty state
- Bulk place on litigation hold
- Export MBOX: trigger download

### 5.6 — Other Admin
- Features: toggle individual feature → saved
- Features: apply "Minimal" preset → multiple toggles change
- Features: apply "Enterprise" preset → multiple toggles change
- Queue: list queued messages
- Queue: retry message → status updated
- Queue: delete message → removed
- System: backup configuration
- System: restart gateway button
- Audit: date filter → filtered results
- Trace: search by sender/recipient → results
- Trace: CSV export → trigger download

---

## Phase 6: Cross-Cutting Edge Cases

### 6.1 — Session & Auth
- Login → session valid for 1 hour
- Refresh token rotation on every access token refresh
- Session expiry: redirect to login with message
- Logout: clears all tokens, redirects to login
- Logout from all devices
- Impersonation: admin sees impersonation banner
- Impersonation: exit returns admin to admin page
- Rate limiting: 5 rapid failed logins → delayed response
- CAPTCHA: after threshold → challenge appears
- Force password change on first login
- MFA enrollment required: message shown

### 6.2 — Network & Offline
- Go offline: offline badge appears
- Compose offline: works (IndexedDB queue)
- Send offline: queued, sent on reconnect
- Archive offline: queued, applied on reconnect
- Go back online: queued mutations replay
- Network failure on API call: error message
- Retry after network failure: succeeds

### 6.3 — Error Recovery
- 500 from server → user-friendly error, not stack trace
- 404 page → styled 404, not blank
- 401 → redirect to login
- 403 → "Access denied" message
- 422 → field-level validation errors
- 429 → rate limit message with retry-after
- WebSocket disconnect: auto-reconnect with backoff
- WebSocket reconnect: state refreshed

### 6.4 — Accessibility
- All modals: Escape closes
- All modals: overlay click closes
- All forms: labels connected to inputs via for/id
- All buttons: keyboard accessible (Enter/Space)
- All interactive: focus-visible outline
- Skip-to-content link present
- Reduced motion: animations disabled when `prefers-reduced-motion`
- Dark mode: all pages render correctly
- Screen reader: aria-live regions for dynamic content

### 6.5 — Mobile
- Login page: renders on 375px width
- Inbox: sidebar hidden, hamburger menu visible
- Inbox: tap hamburger → sidebar slides in
- Inbox: tap overlay → sidebar closes
- Compose: full-width modal on mobile (<768px)
- Calendar: responsive grid on mobile
- Settings: stacked layout on mobile
- Admin: table scrolls horizontally on mobile

### 6.6 — Performance
- Login page: renders in <2s (cold load)
- Inbox: 50 emails render in <3s
- Compose: opens in <500ms
- Calendar month view: renders in <2s
- No memory leaks on page navigation (5+ page changes)
- No duplicate API calls on rapid navigation
