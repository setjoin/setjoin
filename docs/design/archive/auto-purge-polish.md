# Auto-Purge Polish — Spam Retention, Per-Mailbox Config, Litigation Hold Visibility

## Problem

Only deleted items (Trash) auto-purges. Spam-tagged messages accumulate forever. The recovery page hardcodes "30 days" instead of reading the actual config. Per-mailbox retention overrides don't exist. Litigation hold is invisible to users browsing deleted items.

Gmail's model: Trash and Spam both auto-purge after a fixed 30 days. Users can see their deleted/spam items and recover them before the timer expires. The retention period is not user-configurable — it's a system policy.

## Design

### Backend

**New PL/pgSQL function: `purge_spam_messages()`**

Mirrors `purge_deleted_messages()`. For each mailbox, reads the effective spam retention period (mailbox override → system_config → default 30), finds messages with the Spam tag older than that threshold, and DELETEs them. Held messages are skipped via the existing `trg_messages_hold_check` trigger (BZ015 caught per-row with `EXCEPTION WHEN OTHERS`).

**New system_config key: `spam_purge_days`**

Default `"30"`. 0 = disable spam auto-purge entirely. Admin can change it on the retention page.

**New mailbox columns: `deleted_purge_days INT`, `spam_purge_days INT`**

Nullable. NULL means "use the system_config default." A value of 0 means "disable auto-purge for this mailbox." Per-mailbox overrides allow admins to give VIP mailboxes longer retention or disable purging for specific users.

**Resolution order (per mailbox, per purge type):**

```
mailbox.deleted_purge_days ?? system_config.deleted_items_purge_days ?? 30
mailbox.spam_purge_days    ?? system_config.spam_purge_days         ?? 30
```

**pg_cron:** Add one new job entry for `purge_spam_messages()` running daily.

### Spam vs. Junk

The tag system (Phase 17) uses "Spam" as the canonical system tag in the `location` exclusive group. "Junk" exists only as a legacy folder role and IMAP-to-tag alias in migration code. The purge function operates on the "Spam" tag only — there is no separate "Junk" concept to handle.

### Litigation Hold Visibility

Messages with `held = TRUE` are already protected from DELETE by `trg_messages_hold_check`. Both purge functions already handle this (the trigger raises BZ015, caught per-row by the EXCEPTION block). The gap is user/admin visibility:

**Recovery page (`/recover`):**
- Held messages show a lock icon + "On litigation hold" instead of the countdown timer
- The subtitle reads the actual retention period from config, not hardcoded "30 days"
- `daysUntilPurge()` reads the effective retention period from a new JMAP or config endpoint

**Admin mailbox edit page:**
- Litigation hold badge/indicator — when ON, show "Auto-purge suspended: messages on litigation hold are protected from deletion"
- Two new numeric fields: "Deleted items purge after (days)" and "Spam purge after (days)", both with placeholder showing the global default

**Admin mailbox list:**
- Litigation hold status column (boolean badge)

**Admin retention page (`/admin/retention`):**
- Already has `deleted_items_purge_days` input — add `spam_purge_days` next to it

### API Changes

**`GET /admin/system/config`:** Already returns `deleted_items_purge_days`. Add `spam_purge_days`.

**`PUT /admin/system/config`:** Already accepts config updates. Allow `spam_purge_days`.

**`PUT /admin/mailboxes/{id}`:** Already exists. Add `deleted_purge_days` and `spam_purge_days` fields (optional, nullable).

**`GET /auth/me` or JMAP session:** Expose the effective retention values so the recovery page can read them. Simplest approach: add a `purge_config` object to the JMAP session response with `deletedPurgeDays` and `spamPurgeDays` integers.

### Data Flow

```
Admin sets spam_purge_days = 30 on retention page
  → PUT /admin/system/config { spam_purge_days: "30" }
  → system_config row updated
  → pg_cron runs purge_spam_messages() daily
  → reads system_config.spam_purge_days (30)
  → reads mailbox.spam_purge_days overrides (NULL for most)
  → DELETE FROM messages WHERE id IN (
      SELECT m.id FROM messages m
      JOIN message_tags mt ON mt.message_id = m.id
      JOIN tags t ON t.id = mt.tag_id AND t.name = 'Spam'
      WHERE m.received_at < NOW() - (effective_days || ' days')::INTERVAL
    )
  → held messages raise BZ015 → caught → skipped

User visits /recover
  → page loads, reads purge_config from JMAP session
  → daysUntilPurge(email.deletedAt) uses actual config value
  → held messages render with lock icon + "On litigation hold"
```

### Scope

| Layer | What | Lines |
|-------|------|-------|
| SQL schema | `mailboxes.deleted_purge_days`, `mailboxes.spam_purge_days` columns | ~15 |
| SQL migration | `spam_purge_days` system_config seed + `purge_spam_messages()` function + pg_cron entry | ~60 |
| Go admin API | Update mailbox + config handlers for new fields | ~25 |
| Go JMAP session | Add `purge_config` to session response | ~15 |
| Recovery page | Dynamic retention + held badges + config subtitle | ~30 |
| Admin mailbox page | Purge override fields + hold status badge | ~40 |
| Admin retention page | Spam purge config field | ~15 |
| Admin mailbox list | Litigation hold column | ~10 |
| **Total** | | **~210 lines** |
