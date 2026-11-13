# Compliance Polish + Content Search & Purge

## Summary

Three-part cleanup and expansion of Phase 14 (Compliance):

1. **Archive mailbox removal** — delete stale `'archive'` type references from schema, reducers, Go handlers, docs, and frontend (the feature is deferred to Phase 39)
2. **eDiscovery fixes & restyle** — fix three backend bugs (FTS mismatch, ignored filters, missing MBOX bodies) and restyle the frontend to the Prism/Liquid Glass design system
3. **Content Search & Purge** — new admin page for cross-mailbox FTS search with mass-delete, separate from eDiscovery's hold/export purpose

---

## Part 1: Archive Mailbox Removal

### Rationale

Archive mailbox provisioning was never implemented. The `mailboxes.type` CHECK constraint accepts `'archive'`, the `archive_after_days` column exists, and `enforce_retention()` has a comment about it — but zero Go code references any of it. Phase 14 is marked complete; archive mailbox is deferred to Phase 39 placeholder. Cleaning up stale references prevents confusion.

### Schema changes

**`mailserver/sql/schema/004_mailboxes.sql`**
- Line 8: Remove `'archive'` from CHECK constraint: `CHECK (type IN ('personal','shared','resource','distribution','journal'))`
- Line 2: Update comment to remove "archive"
- Lines 33-34: Remove `archive_after_days` column entirely

**New migration** at `mailserver/sql/migrations/V<NEXT>__remove_archive_mailbox.sql`:
```sql
-- Safety: no code ever created rows with type='archive', so this is DDL-only
ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS mailboxes_type_check;
ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_type_check
  CHECK (type IN ('personal','shared','resource','distribution','journal'));
ALTER TABLE mailboxes DROP COLUMN IF EXISTS archive_after_days;
```

### Reducer changes

**`mailserver/sql/reducers/retention.sql`** lines 42-45:
- Replace the multi-line comment about Phase 14.1 with a concise one-liner: `-- Only 'delete' action is processed; 'hold' is a no-op.`

### Go handler changes

**`mailserver/gateway/internal/handlers/admin_retention.go`** lines 95-96:
- Remove `"archive"` from action validation: `if req.Action != "delete" && req.Action != "hold"`
- Update error message: `"action must be delete or hold"`

### Documentation changes

- `docs/phases.md`: Remove "archive mailbox" from Phase 39 forward reference (line 55-57)
- `CLAUDE.md` line 186: Fix stale text — remove "archive mailbox" (eDiscovery UI is done, archive mailbox is removed)
- `docs/specs/COMPETITIVE_ANALYSIS.md` line 216: Remove "missing dedicated archive" note
- `docs/specs/JMAP.md` line 58: Remove archive mailbox from accountId example

### Frontend change

**`mailserver/webmail/src/routes/admin/mailboxes/+page.svelte`** line 248:
- Remove `"e.g. archive"` placeholder text

---

## Part 2: eDiscovery Fixes & Restyle

### Backend Fixes

All in `mailserver/gateway/internal/handlers/admin_ediscovery.go`:

**Fix 1: FTS language mismatch (bug)**
- tsvector columns are built with `to_tsvector('simple', ...)` (no stemming) but searched with `plainto_tsquery('english', ...)` (stemming)
- Fix: change query to `plainto_tsquery('simple', $N)` to match the index

**Fix 2: Date/from/mailbox filters ignored (bug)**
- `executeSearch()` accepts `dateFrom`, `dateTo`, `fromAddr`, `mailboxIds` in the JSONB query but only applies `keywords` to the SQL
- Fix: extend the search query with optional WHERE clauses:
  - `dateFrom`/`dateTo` → `AND m.received_at >= $N` / `AND m.received_at <= $N`
  - `fromAddr` → `AND m.from_addr ILIKE '%' || $N || '%'`
  - `mailboxIds` → `AND m.mailbox_id = ANY($N::bigint[])`

**Fix 3: MBOX export missing message bodies**
- Current export writes chain-of-custody headers but placeholder comment where message body should be
- Fix: fetch blob data from S3/MinIO for each message's body, write RFC822 content after the MBOX `From ` line
- The handler already has access to the S3 client pattern; inject the storage client into `AdminEDiscoveryHandler`

### Frontend Restyle

**`mailserver/webmail/src/routes/admin/ediscovery/+page.svelte`** — rewrite to follow the retention page pattern (zero scoped `<style>`, all global classes).

Target structure:
```html
<header class="page-header">
    <h1>eDiscovery</h1>
</header>

<div class="search-bar">
    <input class="input" type="search" placeholder="Keywords (body/subject search)" bind:value={keywords} />
    <input class="input" type="text" placeholder="From address" bind:value={fromAddr} />
    <button class="btn btn-primary" onclick={startSearch} disabled={loading}>Search</button>
</div>

{#if loading && !results.length}
    <div class="empty-state">
        <div class="empty-state-icon">🔬</div>
        <div>Searching... {searchStatus}</div>
    </div>
{:else if results.length === 0 && !loading}
    <div class="empty-state">
        <div class="empty-state-icon">🔬</div>
        <div>Enter keywords and click Search to find messages across all mailboxes.</div>
    </div>
{:else}
    <div class="card">
        <div class="card-header">
            <span>{results.length} results ({searchStatus})</span>
            <div style="display:flex;gap:0.5rem">
                <button class="btn btn-ghost btn-sm" onclick={holdSelected} disabled={selected.size === 0}>
                    Hold ({selected.size})
                </button>
                <button class="btn btn-primary btn-sm" onclick={exportSelected} disabled={selected.size === 0}>
                    Export ({selected.size})
                </button>
            </div>
        </div>
        <table class="data-table">
            <thead><tr><th>#</th><th>Subject</th><th>From</th><th>Mailbox</th><th>Date</th></tr></thead>
            <tbody>
                {#each results as r}
                    <tr>
                        <td><input type="checkbox" checked={selected.has(r.id)} onchange={() => toggleSelect(r.id)} /></td>
                        <td>{r.subject}</td>
                        <td>{r.from}</td>
                        <td>{r.mailbox}</td>
                        <td>{new Date(r.receivedAt).toLocaleDateString()}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}
```

Changes from current:
- Remove all 12 lines of scoped `<style>`
- Replace `.toolbar` with `.search-bar` and `class="input"`
- Replace `.btn-primary` with `class="btn btn-primary"`
- Replace custom table with `class="data-table"`
- Wrap results in `class="card"` with `card-header` for actions bar
- Use `class="empty-state"` for loading/empty states
- Dark mode is automatic via token inheritance
- Date/from/mailbox filter inputs added to search bar (backend now supports them)

### Route changes

No new routes. eDiscovery routes remain:
- `POST /admin/ediscovery/search`
- `GET /admin/ediscovery/{id}`
- `POST /admin/ediscovery/hold`
- `GET /admin/ediscovery/export`

---

## Part 3: Content Search & Purge (New)

### Purpose

Separate incident-response tool for finding and deleting messages across all mailboxes. Unlike eDiscovery (legal hold and forensic export, super_admin only), this is for scenarios like "a phishing email hit 47 inboxes — find and purge all copies."

### Backend

**New file: `mailserver/gateway/internal/handlers/admin_content_search.go`**

`AdminContentSearchHandler` with two methods (search is synchronous — no async polling needed for incident response):

| Method | Route | Description |
|--------|-------|-------------|
| `Search` | `POST /admin/content-search/search` | Cross-mailbox FTS search, returns results directly (max 500) |
| `DeleteSelected` | `POST /admin/content-search/delete` | Hard-delete selected messages across mailboxes |

Search is synchronous because incident-response result sets are typically small (a specific phishing email across inboxes). Uses the same FTS pattern as eDiscovery (`plainto_tsquery('simple', ...)` against `body_tsv`/`subject_tsv`/`from_tsv`) with full filter support (keywords, date range, from address, mailbox IDs) from the start.

`DeleteSelected` request body:
```json
{
  "ids": [1, 2, 3],
  "reason": "Phishing email cleanup — subject 'Urgent password reset' from fake@example.com"
}
```

`DeleteSelected` calls a new PL/pgSQL reducer that:
1. Verifies each message exists
2. Hard-deletes each message (permanent removal from `messages` table)
3. Skips messages under litigation hold (hold trigger blocks DELETE at DB level; caught per-row)
4. Writes `admin_audit_log` entry with the reason, admin user ID, message count, and affected mailbox IDs
5. Returns count of deleted, held (skipped), and not-found

No separate search-results table is needed — search is synchronous, results are ephemeral.

**Route registration in `main.go`:**
```go
mux.Handle("POST /admin/content-search/search",  adminLimit(requireAdmin(contentSearchH.Search)))
mux.Handle("POST /admin/content-search/delete",  adminLimit(requireAdmin(contentSearchH.DeleteSelected)))
```

### New PL/pgSQL Reducer

**`mailserver/sql/reducers/content_purge.sql`**:

```sql
CREATE OR REPLACE FUNCTION content_purge_messages(
  p_message_ids  BIGINT[],
  p_admin_user   TEXT,
  p_reason       TEXT
) RETURNS TABLE(deleted_count INT, held_count INT, not_found_count INT) AS $$
```

Hard-deletes messages by ID across mailboxes. Messages under `litigation_hold` are skipped (the DELETE trigger blocks them at the DB level; caught per-row with EXCEPTION). Writes a single `admin_audit_log` row with: admin user, reason, message count, deleted IDs, affected mailbox IDs, timestamp.

### Frontend

**New file: `mailserver/webmail/src/routes/admin/content-search/+page.svelte`**

Follows the identical Prism design pattern as the restyled eDiscovery page — zero scoped `<style>`, all global classes. Key differences from eDiscovery:
- Search is synchronous (no polling); results display immediately
- Single action button: **Delete Selected** with `class="btn btn-danger"` (red)
- Delete triggers confirmation modal with required reason field:
  - "Permanently delete N messages from M mailboxes?"
  - Text input for reason (required, min 10 chars): "e.g. Phishing email cleanup — subject 'Urgent password reset'"
  - Cancel / Confirm Delete buttons
- Success state shows counts: "Deleted 47 messages. 2 messages skipped (on litigation hold)."
- Role: `super_admin` only (destructive operation)

### Admin Layout

Add nav entry in [admin/+layout.svelte](mailserver/webmail/src/routes/admin/+layout.svelte):
```ts
{ label: 'Content Search', path: '/admin/content-search', icon: '🔎', role: 'super_admin' },
```

---

## Testing

- eDiscovery: existing `admin.test.ts` smoketests updated for new class names
- Content Search: new smoketest verifying page mount
- Backend: Go table-driven tests for FTS query construction, filter application, delete reducer
- SQL: pgTAP test for `content_purge_messages()` verifying soft-delete + audit log + hold skip

---

## Files Summary

| Action | File |
|--------|------|
| **Modify** | `mailserver/sql/schema/004_mailboxes.sql` |
| **Create** | `mailserver/sql/migrations/V<NEXT>__remove_archive_mailbox.sql` |
| **Modify** | `mailserver/sql/reducers/retention.sql` |
| **Modify** | `mailserver/gateway/internal/handlers/admin_retention.go` |
| **Modify** | `mailserver/gateway/internal/handlers/admin_ediscovery.go` |
| **Modify** | `mailserver/webmail/src/routes/admin/ediscovery/+page.svelte` |
| **Modify** | `mailserver/webmail/src/routes/admin/mailboxes/+page.svelte` |
| **Create** | `mailserver/gateway/internal/handlers/admin_content_search.go` |
| **Create** | `mailserver/sql/reducers/content_purge.sql` |
| **Modify** | `mailserver/gateway/cmd/gateway/main.go` |
| **Create** | `mailserver/webmail/src/routes/admin/content-search/+page.svelte` |
| **Modify** | `mailserver/webmail/src/routes/admin/+layout.svelte` |
| **Modify** | `docs/phases.md` |
| **Modify** | `CLAUDE.md` |
| **Modify** | `docs/specs/COMPETITIVE_ANALYSIS.md` |
| **Modify** | `docs/specs/JMAP.md` |
