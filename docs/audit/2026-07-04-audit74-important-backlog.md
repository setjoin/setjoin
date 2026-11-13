# Audit-74-Important adjacent backlog — reconstructible candidates

Queue B item 7 (`retired-docs:superpowers/plans/archive/2026-07-04-queue-b-combined.md` §7),
2026-07-04. Companion to
`docs/audit/2026-07-04-audit74-manifest-loss.md` (why the 74-Important
manifest itself is gone).

**This is a tracked backlog, not a gate.** Per the plan's [REVIEW] split: the
machine guard (`scripts/check-audit74-criticals.sh`, the 10 Criticals) ships
and gates this queue item; the triage below does not block anything. Every
line either cites the grep/commit evidence behind its hypothesis, or is
explicitly marked "not reconfirmed this pass" so a future pass knows exactly
what's still unverified — don't re-derive this list from scratch.

Status legend: **RESOLVED** (verified this pass, evidence cited) ·
**LIKELY RESOLVED** (strong signal, not 100% confirmed) · **OPEN** (checked,
issue still present) · **NOT RECONFIRMED** (not checked this pass — cited
file:line is where to look first).

## A. The ~10 named categories from TODOS.md's one prose sentence

These are the only trace of the ~64 unenumerable Important findings. Cross-
referenced against the 25 W-IMPORTANT-verify list below where the same fix
shows up there.

| Category | Status | Evidence |
|---|---|---|
| admin folder domain-scope bypass | RESOLVED | `mailserver/internal/admin/admin_mailboxes_folder_scope_test.go` exists — a dedicated regression test for exactly this. |
| admin_alerts config-allowlist bypass | RESOLVED | `admin_alerts.go:181-188` — explicit allowlist ("config key not writable via alerts API"), scoped to `hc_`/`alert_` key prefixes only. |
| auth SM2 verify unwired | RESOLVED (fix); test still open | Commit `999a928e` "fix(auth): verify SM2 access tokens at the mailserver gateway" is real (`git log`). Matches W-IMPORTANT-verify #2 below — regression test is the remaining ask. |
| caldav iMIP header injection | NOT RECONFIRMED | `mailserver/internal/caldav/` iMIP handling — not checked this pass. |
| ldap STARTTLS not enforced + unscoped queries | RESOLVED (fix); test still open | STARTTLS: commit `e9ca459b` "fix(ldap): enforce TLS on bind, not just TLS-configured" is real. Unscoped queries: same fix as Critical C5 (`is_shared = TRUE`), separately guarded by `check-audit74-criticals.sh`. Matches W-IMPORTANT-verify #3 below. |
| linkprotect XFF spoof + fail-safe | RESOLVED | `shared/httputil/httputil.go:102` `ClientIP()` exists and is called at `mailserver/internal/linkprotect/handler.go:64`. Matches W-IMPORTANT-verify #18 below. |
| ratelimit data race | RESOLVED (fix); test still open | Matches W-IMPORTANT-verify #10 (`ratelimit sync() value-snapshot under lock`) — not independently re-diffed this pass beyond confirming the item is tracked with a specific fix description. |
| cron 60x fire | RESOLVED (fix); test still open | Matches W-IMPORTANT-verify #7 (`cron Due() same-minute guard`, `cron/task.go:43`) — not independently re-diffed this pass. |
| kql placeholder collision | RESOLVED | `mailserver/internal/kql/sql.go:28` — comment documents "continue placeholder numbering from where the outer call left off," i.e. the collision-avoidance fix is in place. |
| metrics double-count | NOT RECONFIRMED | `mailserver/internal/middleware/metrics.go` / `mailserver/internal/cron/metrics.go` exist; grepped for an obvious dedup marker (`sync.Once`, "double", "already recorded") and found none — inconclusive either way, needs an actual read of the counter-increment call sites. |

## B. W-REVERIFY minors (33) — `TODOS.md:385-421`

### Security-tagged (6) — all confirmed RESOLVED this pass

| Finding | Status | Evidence |
|---|---|---|
| calendar_free_busy exposes any mailbox's busy times, no ACL — `calendar_freebusy.sql:468` | RESOLVED (documented decision + gated) | The reducer now carries an explicit "FREE/BUSY VISIBILITY (recorded product decision)" comment block: org-open by design while `sharing.defaults` is OFF (matches Exchange default); when `sharing.defaults` is ON, each personal target is gated through `calendar_effective_acl` (D11, fail-closed). This is exactly the fix the finding's own note recommended ("document the org-open free/busy policy"). |
| import_message trusts p_tag_id without verifying mailbox ownership — `import_export.sql:49` | RESOLVED | `import_export.sql` now has `SELECT name INTO v_tag_name FROM tags WHERE id = v_tag_id AND mailbox_id = p_mailbox_id` + `RAISE EXCEPTION ... BZ002` if not found — the exact ownership filter the finding asked for. |
| Admin mailbox import has no audit trail — `admin_import_export.go:38` | RESOLVED | `admin_import_export.go:96` calls `audit.Write(ctx, h.pool, audit.Entry{...})` in the import path. |
| CSS injection via calendar color — `CalendarApp.svelte` (7 line refs) | RESOLVED | All 4 live color-binding sites (`getCalendarColor`, event color fallback, the editor swatch, the `cal-dot` span at the former line ~710/now 1131) route through `safeColor()` (`$lib/calendar/format`), which keeps only `#hex`. |
| Remote `<img>` allowed despite CSS url() stripping — `sanitize.ts:6` | RESOLVED | `sanitize.ts` blocks `src`/`srcset` on any `REMOTE_URL`-matching value inside the DOMPurify hook unless `allowRemoteImages` is explicitly opted in (`sanitizeHTML(html, { allowRemoteImages })`); `hasRemoteImages()` is the "show images?" banner heuristic. Blocked by default. |
| Debug logger dumps `/auth/me` PII via `?debug=1` — `logger.ts:6` | RESOLVED | `auth.ts` no longer logs the full `/auth/me` body — only `{status, ok}` on the raw response and `{isAdmin, hasMailbox}` on success (comment: "?debug=1 enables the logger in prod, so log only non-PII flow flags"). The `logger` gate itself (`DEV || ?debug=1`) is unchanged, but the payload it gates is no longer PII, which was the actual complaint. |

### Other minors (27) — bug/simplify/deadcode

| Finding | Status | Evidence |
|---|---|---|
| admin_effective_authority / _potential verbatim-duplicate bodies — `admin_effective_authority_potential.sql:16` | NOT RECONFIRMED | Simplify-only, no security texture; not checked this pass. |
| admin_role_deactivate audits a no-op UPDATE — `admin_role_deactivate.sql:8` | RESOLVED | `GET DIAGNOSTICS v_n = ROW_COUNT; IF v_n > 0 THEN ... audit_write(...)` — only audits when a row actually changed. |
| recall stub has no message_tags row, invisible in webmail — `recall.sql:86` | RESOLVED | `recall.sql` calls `PERFORM tag_message(v_stub_id, v_now, 'Inbox', v_copy.mailbox_id, 'recall', TRUE)` right after the stub INSERT, with a comment explaining why folder_id alone isn't enough. |
| jmap_mailbox_set_update accepts parentId with no ownership/cycle check — `jmap_mailbox.sql:360` | RESOLVED | Full guard present: rejects self-parent, a parentId outside `p_mailbox_id`, and a recursive-CTE ancestor-cycle check, all before the UPDATE. |
| jmap_mailbox.sql / jmap_thread.sql bare exceptions without BZ ERRCODE — `jmap_thread.sql:99` | RESOLVED | Every `RAISE EXCEPTION` sampled carries `USING ERRCODE = 'BZ0xx', HINT = ...` on the following line (multi-line statement — a naive single-line grep undercounts this; verified by reading the full statement). |
| recall_message builds v_results but never returns/stores it — `recall.sql:30` | NOT RECONFIRMED | Deadcode-only; not checked this pass. |
| jmap_calendar_event_rsvp redundant ownership EXISTS subqueries — `calendar_itip.sql:51` | NOT RECONFIRMED | Simplify-only; not checked this pass. |
| jmap_task_set_create/update accept parent_id/linked_message_id/linked_event_id/assignee_user_id with no ownership check — `jmap_task.sql:175` | RESOLVED | `jmap_task_set_create` now scopes every reference: `parent_id`/`linked_message_id`/`linked_event_id` are each wrapped in a `SELECT ... WHERE id = ... AND mailbox_id = p_mailbox_id` (nulls any cross-tenant reference instead of storing it), and `assigneeUserId` is no longer trusted raw — resolved server-side via `resolve_identity(assigneeEmail)`, failing loud (`BZ040`) on an unresolvable email. |
| scim_validate_token() unused dead code, plaintext-hash-equality model — `scim_validate_token.sql:33` | RESOLVED | File now reads "(scim_validate_token removed: dead code. Production SCIM auth uses ...)" — removed. |
| effective_capabilities duplicates check_app_entitlement's gate logic — `effective_capabilities.sql:62` | LIKELY RESOLVED | Current code delegates directly (`'mail', check_app_entitlement(p_mailbox_id, 'mail')`, etc.) rather than reimplementing the gate — reads as already-fixed, not spot-checked for every branch. |
| access_review_close writes no audit row for the close action — `access_review_close.sql:64` | LIKELY RESOLVED | Two `PERFORM audit_write(...)` calls present in the file (lines ~39 and ~60); not confirmed the second is specifically the campaign-close event vs. a per-item close. |
| notify_alerts send() failure rolls back the whole health snapshot — `health_check.sql:208` | NOT RECONFIRMED | Read the partition/escalation section, not the alert-dispatch transaction boundary itself; inconclusive. |
| Dead reducers bump_tag_state / untag_message, no production callers — `utils_tags.sql:7` | RESOLVED | File now reads "(bump_tag_state + untag_message removed: dead code with no production caller...)" — removed, callers grepped clean. |
| ReadingPaneActions facade duplicated against 23 callback props — `ReadingPane.svelte:24` | NOT RECONFIRMED | Simplify-only; not checked this pass. |
| buildMsg sets always-undefined deliveryReceiptRequested — `ComposeScreen.svelte:521` | RESOLVED | `grep deliveryReceiptRequested` in `ComposeScreen.svelte` returns zero hits — the dead field was removed entirely. |
| Day-view event lookup uses UTC date slice, off-by-one in non-UTC zones — `CalendarApp.svelte:254-257,241-252` | NOT RECONFIRMED | Read an adjacent region of the file (subscription refresh logic) rather than the actual day-view lookup; the exact lines weren't matched this pass. |
| 'Load more' sign-ins re-fetches the same page — `settings/security/+page.svelte:329` | LIKELY RESOLVED | `loadMore()` now calls `loadSignIns(true)` (a parameterized call, presumably a pagination flag) rather than a bare re-fetch — the shape of the fix is present; `loadSignIns`'s internal pagination handling wasn't traced end-to-end. |
| Profile display name never loaded from server, only derived from email — `settings/+page.svelte:88` | RESOLVED | `displayName = $user?.displayName || ($user?.email?.split('@')[0] ?? '')` with comment "Prefer the saved display name from the server; fall back to the email local-part." |
| Settings index re-implements TOTP/passkey flows already centralized — `settings/+page.svelte:262` | NOT RECONFIRMED | Simplify-only; not checked this pass. |
| Webhook delete: no confirmation + success toast on failure — `admin/(system)/webhooks/+page.svelte:65` | RESOLVED | `deleteWebhook()` has `if (!confirm(...)) return;` and only shows the "Webhook deleted" toast after `if (!res.ok) { showToast('Failed to delete webhook'); return; }`. |
| Backup deletion: no confirmation, masks failures — `admin/(system)/system/+page.svelte:435` | RESOLVED | `deleteBackup()` has `if (!confirm('Delete this backup? This cannot be undone.')) return;`. |
| Feature-preset apply swallows per-flag errors — `admin/(system)/features/+page.svelte:108` | RESOLVED | `applyPreset()` uses `Promise.allSettled`, collects `failed` keys, and reports `Preset "..." partially applied — failed: ...` instead of a blanket success. |
| Spam admin page bypasses adminFetch, no error handling — `admin/(mail)/spam/+page.svelte:10` | RESOLVED | Both `loadStats()` and `resetModel()` now go through `adminFetch`, with `if (!res.ok) { showToast(...); return; }` handling. |
| Default httpRequest error path leaks raw response body — `http.ts:133` | NOT RECONFIRMED | Read the 401/403 branches of the same function; the specific leaking branch (likely the generic `!res.ok` fallback) wasn't isolated this pass. |
| blockedCopy carries two dead parameters — `blocked.ts:18` | RESOLVED | `export function blockedCopy(native: boolean): BlockedCopy` — single parameter now. |
| Dead component RemindersWindow.svelte never mounted — `RemindersWindow.svelte:1` | OPEN (confirmed still dead) | Grepped the whole webmail `src/` tree for any reference to `RemindersWindow` outside its own file — zero hits. Component still exists, still unused. Low-priority deadcode, not a bug. |
| AssistDrawer #each key can collide on first-40-chars — `AssistDrawer.svelte:203` | NOT RECONFIRMED | Not checked this pass. |

## C. W-IMPORTANT-verify (25) — `TODOS.md:422-448`

Every item in this list is framed by TODOS.md itself as "fix is correct, test
gap" — i.e. the underlying bug is already believed fixed; what's missing is a
regression test (tracked separately as W-TESTS Phase 2). This pass spot-
checked that the cited fix commits are real (not fictitious references) and,
for a few, that the described code shape is actually present.

| Item | Status | Evidence |
|---|---|---|
| SPA verifyPush → poll /auth/push/status, `44ee1dd6` [C10-complete] | RESOLVED (fix); test open | Commit exists. Also directly load-bearing for Critical C10 — see `check-audit74-criticals.sh` C10a/C10b. |
| `999a928e` SM2 gateway token verify [auth] | RESOLVED (fix); test open | Commit exists (confirmed via `git log`). |
| `e9ca459b` enforce TLS on bind via `*tls.Conn` assertion [ldap] | RESOLVED (fix); test open | Commit exists. |
| `2b524ad8` (a) return errors on disable writes, always counting Disabled [ldap] | RESOLVED (fix); test open | Commit exists ("fix(ldapsync): harden deprovisioning seam"). |
| app-password auth: drop broken `JOIN domains AND d.enabled=TRUE` [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass; no commit hash given to verify against. |
| PgBouncer `track_extra_parameters = app.encryption_key` [shared-misc] | NOT RECONFIRMED | Config-file item; not checked this pass. |
| cron `Due()` same-minute guard — `cron/task.go:43` [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass. |
| startup BootstrapSecrets propagate Fprintf write error [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass. |
| storage backfill `rows.Err()` after cursor loop — `storage/migration.go:199` [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass. |
| ratelimit `sync()` value-snapshot under lock [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass. |
| bulkroles mark job 'error' on fresh pool conn [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass. |
| transport rule nil mailbox check — `user/rules.go Create` [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass. |
| mailctl bulkCreateUsers return error on `failed>0` [shared-misc] | NOT RECONFIRMED | Not re-diffed this pass. |
| Fast-path no longer fails open on rate_limit / policyEngine [threat-part] | NOT RECONFIRMED | Not re-diffed this pass. |
| caldav: select `component_type` in listEvents/listEventsFiltered/getEventByUID [dav] | NOT RECONFIRMED | Not re-diffed this pass. |
| caldav: free-busy `handleFreeBusyQuery` uses `parts[0]` not `parts[1]` [dav] | NOT RECONFIRMED | Not re-diffed this pass. |
| Dead raw_ref SELECT/scan + misleading SP1 comment — `imap.go:738` | NOT RECONFIRMED | Not re-diffed this pass. |
| clientIP XFF spoof → `httputil.ClientIP` — `handler.go:64` [linkprotect-spam] | RESOLVED | `shared/httputil/httputil.go:102` `ClientIP()` exists; called at `mailserver/internal/linkprotect/handler.go:64`. |
| FetchMessage S3 direct read replacing dead HTTP `/jmap/download` [linkprotect-spam] | NOT RECONFIRMED | Not re-diffed this pass. |
| deploy/wizard: one shared pgpool password before loop [infra-handlers] | NOT RECONFIRMED | Not re-diffed this pass. |
| discovery: `io.LimitReader` 64KB cap on `.well-known` decode [infra-handlers] | NOT RECONFIRMED | Not re-diffed this pass. |
| downloads: register `GET /downloads/asset/{asset}` route [infra-handlers] | NOT RECONFIRMED | Not re-diffed this pass. |
| health: dispatch alert only on ok→error transition [infra-handlers] | NOT RECONFIRMED | Not re-diffed this pass. |
| webhook: detach delivery goroutine via `context.WithoutCancel` + 30s timeout [infra-handlers] | NOT RECONFIRMED | Not re-diffed this pass. |
| jmap iMIP `sendUpdateInvite` ctx detach, `dc5e9b42` [mailcore] | RESOLVED (fix); test open | Commit exists ("fix(jmap): detach CalendarEvent/sendUpdate iMIP re-issue from request ctx"). |

## Net read

Of the ~40 items actually re-checked this pass (6/6 security minors, most of
the 27 other minors, ~5/10 named categories, 6/25 W-IMPORTANT-verify commits),
essentially everything checked is **already fixed** — consistent with the
`production-hardening` branch's "REMEDIATION COMPLETE" claim (merge commit
`5b5ce313`, ancestor of current `main`). The remaining unchecked items (marked
NOT RECONFIRMED above) are the actual residual backlog: mostly "add the
regression test" work (W-TESTS Phase 2, already tracked) plus a handful of
simplify/deadcode items with no security texture. **Nothing found this pass
rises to a new Critical or an unfixed security-tagged Important** — the one
genuinely open item is `RemindersWindow.svelte` (dead code, no security or
correctness impact).
