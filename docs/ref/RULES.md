# Rules Engine — Spec

Implementation plan for Phase 5 of TODO.md, plus a record of what Phase 1
already delivered. Rules are the mechanism through which users (and
admins, via transport rules) automate per-message handling.

## Two-tier execution model

Every rule carries a `run_on` column that decides where it evaluates:

| `run_on` | Evaluates where | Suitable actions |
|---|---|---|
| `server` | `apply_rules()` PL/pgSQL at delivery, before the message lands in the user's inbox | `move_to`, `copy_to`, `forward_to`, `redirect_to`, `flag`, `categorize`, `mark_read`, `delete`, `discard`, `add_header`, `remove_header`, `set_spam_score`, `notify_admin`, `bcc_to`, `stop_processing` |
| `client` | Client engine (JS / Swift / Kotlin) after JMAP sync | `highlight_color`, `play_sound`, `desktop_notification`, `local_move` |
| `both` | Server handles the delivery-side actions, client handles the presentation-side actions on the same rule | union of the two lists above |

The `conditions` match equally in both engines — the client reuses the
server's condition grammar verbatim so rule-authors don't have to learn
two vocabularies.

## Row shape (schema)

`sql/schema/009_rules.sql` — already live:

```sql
rules (
  id, user_id, mailbox_id,
  name, enabled,
  priority          INT,       -- lower = runs first
  run_on            'server' | 'client' | 'both',
  is_transport_rule BOOL,      -- admin-only; runs before user rules
  conditions        JSONB,     -- [{field, op, value}, ...]
  actions           JSONB,     -- [{type, params}, ...]
  stop_processing   BOOL,
  created_at, updated_at
)
```

Indexes: `(mailbox_id, enabled, priority)` for user rules, a partial on
`(enabled, priority) WHERE is_transport_rule` for admin rules.

## Condition grammar

**Fields** (`v_cond->>'field'`) supported by `eval_condition()`:

| Field | Source | Notes |
|---|---|---|
| `from_addr` | `messages.from_addr` | lowercased |
| `subject` | `messages.subject` | lowercased |
| `body` | `messages.body_text` | lowercased; HTML-only messages have empty body_text today |
| `spam_score` | `messages.spam_score` | numeric |
| `size_bytes` | `messages.size_bytes` | numeric |
| `has_attachments` | `messages.has_attachments` | boolean |
| `sender_domain` | `split_part(from_addr,'@',2)` | lowercased |

**Operators** (`v_cond->>'op'`):

| Op | Behaviour |
|---|---|
| `contains` / `not_contains` | substring, case-insensitive |
| `equals` / `not_equals` | full-match, case-insensitive |
| `starts_with` | prefix, case-insensitive |
| `gt` / `lt` | numeric compare (cast from text) |
| `is_true` | boolean match against `'true'` |
| `matches_regex` | POSIX regex via `~` |
| `in_list` | comma-separated literal set |

### Missing today, planned for 5.1

- **`to_addr`** and **`cc_addr`** — messages.to_addrs / cc_addrs are
  JSONB arrays, not scalars; `eval_condition()` needs a
  `jsonb_array_elements + ->>'email'` path. Common Outlook rule
  ("to me specifically") is impossible without this.
- **`recipient_count`** — folder-list-noise filtering.
- **`header_{name}`** — we don't parse arbitrary headers yet; plumb
  through `spam_headers` + inbound header capture.
- **`list_id`** — derive from `List-ID` header; important for mailing
  list filtering.
- **OR-grouping** — evaluator is AND-only (`v_matched := FALSE; EXIT`).
  Outlook wizard requires `(A OR B) AND (C OR D)` at minimum. Proposed
  JSONB shape (matches JMAP `FilterOperator` for consistency):

  ```json
  { "operator": "AND",
    "conditions": [
      { "operator": "OR", "conditions": [ {...A}, {...B} ] },
      { "operator": "OR", "conditions": [ {...C}, {...D} ] }
    ] }
  ```

  An array-of-leaf is the degenerate case `{operator:"AND", conditions:leaves}`
  — existing rows keep working without migration.

## Action catalog

**Already implemented in `apply_action()`**:

| type | params | Behaviour |
|---|---|---|
| `move_to` | `{folder: "..."}` OR `{role: "inbox|sent|drafts|..."}` | Calls `set_message_location()` — replaces all location-group tags, trigger enforces exclusivity |
| `mark_read` | — | Sets `is_read = TRUE`, decrements unread count on ALL tags via trigger |
| `delete` | — | Calls `set_message_location('Trash')` — trigger removes current location |
| `discard` | — | Hard-delete; skipped if mailbox is on `litigation_hold` |
| `forward_to` | `{address: "..."}` | Inserts a copy into `outbound_queue` from a `noreply-forward@<primary-domain>` sender |
| `add_header` | `{value: "..."}` | Stores into `spam_headers` under key `X-Rule-{rule_id}` |

**Planned for 5.1** (not yet implemented):

- `copy_to` — duplicate message row into a second folder
- `redirect_to` — same as forward but preserves original From (depends on 4.2 SMTP submission being live)
- `notify_admin` — dispatch to an admin-audit queue
- `bcc_to` — transport-rule companion; adds silent recipient
- `set_spam_score` — let DLP rules nudge scores
- `remove_header` — counterpart to add_header
- `stop_processing` — currently represented as the row-level
  `stop_processing` column; consider whether an action form is needed
  (most engines conflate the two — keep the column and remove the
  action plan)

The unknown-type default in `apply_action()` is `NULL` (silently
skipped). Keep that behaviour; rules authored against a newer server
can still be dormant on older ones.

## Execution order

`apply_rules()` (see `sql/reducers/rule_engine.sql`) processes rules in
strict priority order:

```sql
ORDER BY r.is_transport_rule DESC,   -- admin transport rules first
         r.priority ASC,              -- lower number wins
         r.id ASC                     -- stable tiebreak
```

Within a single rule:

1. Evaluate every condition (AND). Any falsehood short-circuits to the
   next rule.
2. For each matched rule, loop through `actions[]` and apply each. The
   message record is reloaded between actions so later actions see
   earlier edits (e.g. `mark_read` → tag counter change is visible
   to the next action's tag lookup).
3. Emit `trace(... 'rule_applied')` with `{rule_id, rule_name}`.
4. If `stop_processing`, break the outer loop.

### Where rules are invoked

- `deliver()` — calls `apply_rules(msg_id, now, mailbox_id, 'server')`
  AFTER the message + tag association is committed, BEFORE the
  `pg_notify('tag:...')`. So rule-moved messages land in the right
  tags of the very first push clients receive.
- `send()` — calls `apply_rules(msg_id, now, mailbox_id, 'outbound')`
  AFTER the Sent-folder insert but within the same transaction. A DLP
  `discard` action (or any action that raises an exception) rolls back
  the entire submission — the Sent copy, quota bump, and queue insert
  are all undone. The user never sees a "sent" message that never
  actually went out. (Step 5 of send.sql.)

## Transport rules (admin; 5.4)

Same `rules` table, flagged `is_transport_rule = TRUE`, `mailbox_id IS NULL`.

Three canonical forms:

- **Disclaimer** — `add_header` + `append_body` (new action, stores a
  snippet in `messages.body_text` / `body_html`). Runs in `send()` so
  external recipients see it; skip internal-only traffic via a
  `recipient_domain != local` condition.
- **BCC archiving** — `bcc_to` with a journal mailbox address. Runs in
  both `deliver()` and `send()` per the journaling policy.
- **DLP block** — `discard` (or a new `quarantine` action that moves
  to an admin-review tag) gated on regex match.

Admin UI must distinguish transport rules from user rules visibly:
different list in the admin console, not mixed into the per-user
"Rules" screen.

## JMAP sync (5.2, 5.3)

The client engine runs rules whose `run_on IN ('client', 'both')`.
Phase 5.2 wires a new JMAP type and two methods:

```
Rule/get     — returns all rules visible to the account
Rule/set     — create/update/destroy rules
Rule/changes — diff by rules.updated_at > $since
```

State token source: add `jmap_rule_state BIGINT` to `mailboxes`, bumped
whenever any rule for that mailbox changes (trigger).

Client-side engine is deliberately unsophisticated: evaluate the same
JSONB conditions locally (shared JSON schema; pluggable ops), then
invoke platform-specific effects (browser notification, sound,
OS-level mail category colour). Clients MUST NOT attempt server-side
actions — `move_to`, `flag`, etc. round-trip through JMAP even if they
appear in `both` rules, so server state remains authoritative.

## Test-rule-against-existing-mail

A UX requirement from 5.3 ("test rule against existing mail") needs a
dry-run mode on the evaluator:

```sql
CREATE FUNCTION test_rule(p_rule_id BIGINT, p_limit INT)
RETURNS TABLE (message_id BIGINT, would_match BOOL, would_apply JSONB)
```

Implementation: select the newest N messages for the rule's mailbox,
run the same `eval_condition()` loop, but instead of calling
`apply_action()`, serialize each action to JSONB and return it. The
JMAP client renders "Would move 12 messages to 'Projects'".

## Open questions

- **Rule versioning & conflict** when two clients edit the same rule
  offline. Latest-write-wins is fine for v1; revisit if admins push
  back.
- **Rate limits on `forward_to`** — an email-loop between two
  auto-forwarders is a classic DOS. Add a per-rule counter in
  `rate_limit_counters` keyed by `forward:{rule_id}`; bail after N per
  hour.
- **Regex safety** — `matches_regex` currently trusts user-authored
  patterns. A catastrophic-backtracking regex hangs the delivery
  worker. Validate with `regexp_match` wrapped in a `statement_timeout`
  or switch to a non-backtracking engine (RE2) in the client path.
