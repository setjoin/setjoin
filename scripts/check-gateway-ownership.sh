#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-gateway-ownership.sh — POSITIVE per-user-isolation guard for the RAW
# gateway query surface (the IMAP/SMTP/CalDAV/CardDAV/JMAP/admin Go layer that
# the reducer-only check-account-scope.sh never covers).
#
# WHY THIS EXISTS (ARCH-006). Per-user isolation (R4) is enforced at the
# APPLICATION layer — `p_mailbox_id` propagation in reducers + raw gateway WHERE
# clauses — not by native PostgreSQL RLS (deferred; see
# docs/adr/ARCH-006-app-level-isolation-posture.md and
# retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md). Deferring RLS makes
# the steady state FAIL-OPEN: a forgotten ownership predicate leaks cross-mailbox
# rows, and nothing at the DB layer denies it. check-account-scope.sh is NEGATIVE
# (it pattern-matches known-bad shapes), so a NEW raw query that simply OMITS
# scoping sails through it. This guard closes that hole: it is POSITIVE — every
# raw gateway query that TOUCHES a user-data table must CARRY a scoping token, OR
# be on the explicit, reason-commented allowlist below. A new unscoped query
# fails CI. This is the load-bearing compensating control that makes the RLS
# deferral safe (ARCH-006 decision 3), not optional polish.
#
# MECHANISM (mirrors check-account-scope.sh idioms — comment-strip, awk over Go
# backtick SQL literals, portable BSD+GNU awk):
#   1. Extract every backtick-delimited string literal from mailserver/internal
#      *.go (excluding _test.go), collapsing tabs/newlines to single spaces so a
#      multi-line SQL literal is ONE record (Go indents SQL with tabs).
#   2. Keep only literals that TOUCH a user-data table — FROM / JOIN / UPDATE /
#      INSERT INTO / DELETE FROM <user-data table>. Reducer CALLS
#      (`SELECT fn($1,…)` / `SELECT * FROM fn($1)`) are NOT raw table access and
#      are skipped (they are covered by check-account-scope.sh).
#   3. PASS a literal if it CARRIES a scoping token IN A PREDICATE CONTEXT:
#      mailbox_id | user_id | account_id | domain_id (the ownership currencies),
#      OR an FK-collection handle that is itself mailbox-owned (tag_id |
#      folder_id | calendar_id | addressbook_id — an IMAP folder / a calendar /
#      an address book all carry a mailbox_id one hop away, and the handle was
#      resolved from the session mailbox). PRECISION (2026-06-18): the token must
#      appear in a WHERE / JOIN…ON / AND / OR / HAVING / USING clause (or the
#      WHERE of an UPDATE/DELETE) — NOT in a SELECT projection, an INSERT column
#      list, a VALUES list, or a RETURNING clause (predicate_context() blanks
#      those regions first). A token that only labels a returned/inserted column
#      does not SCOPE rows (this is exactly the recall.go:56 IDOR shape). An
#      INSERT therefore never passes on its column-list token alone; an INSERT
#      that sets its ownership column from auth (R2) is allowlisted as R2-INSERT.
#      Otherwise the literal must match an allowlist entry; else FAIL.
#
# COVERAGE (the R4 surface this guard actually checks — keep in sync with UDT_RE
# and DATABASE_SECURITY.md R4). Per-user tables guarded: messages, message_tags,
# tags, quarantined_messages, mailboxes, contacts, contact_groups,
# contact_group_members, calendars, calendar_events, addressbooks, tasks,
# aliases, rules, vacation_settings, read_receipts, folders, message_snooze,
# signatures, drafts, user_spam_model, user_sender_list, user_smime_certs,
# user_signatures, user_imap_settings, message_attachments (owned transitively
# via message_id → messages), app_passwords, sessions. NOT guarded (org-wide /
# admin-only / system by design, outside the per-user R4 boundary): message_trace
# and other journal/trace tables, system_config, domains, feature_toggles,
# signing_keys, threat/audit tables.
#
# RESIDUAL (stated honestly, for ARCH-006). This guard asserts a scoping token is
# PRESENT in a PREDICATE context of the statement's text; it does NOT prove the
# token is bound to the AUTHENTICATED user's value (a query could carry
# `mailbox_id = $1` with $1 from req.* — that is R2's job, caught by review + the
# negative checks). It does not blank an UPDATE … SET column list, so a token in
# a SET assignment could count (rare; an UPDATE that mutates mailbox_id is itself
# review-worthy). It cannot see through Go string concatenation of a WHERE clause,
# nor a subquery/CTE/prior-statement ownership check the awk can't relate (those
# literals are allowlisted with a reason). An allowlisted query that later changes
# shape keeps its allowlist pass until re-reviewed. Native RLS (deferred) is what
# finally makes this fail-closed at runtime. Within those bounds this guard makes
# both "a brand new raw gateway query that forgets ownership scoping entirely" and
# "a query that carries an ownership column only in its projection/RETURNING (the
# recall.go:56 IDOR)" un-mergeable.
#
# Usage: scripts/check-gateway-ownership.sh   (exit 0 = clean, 1 = violation).
# Wired into scripts/test.sh (selftest-first).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

# GATEWAY_DIR may be overridden (used by the guard's own self-test) — defaults to
# the real gateway tree.
GATEWAY="${GATEWAY_DIR:-$ROOT/mailserver/internal}"

# ── User-data tables (the R4 surface). Touching any of these without a scoping
# token (or an allowlist entry) is a potential cross-mailbox leak. Trace/journal
# tables (message_trace), system/config tables (system_config, domains,
# feature_toggles, signing_keys, …) and threat/audit tables are NOT here — they
# are org-wide or admin-only by design and out of the per-user R4 boundary.
#
# Each table below was verified per-user (carries mailbox_id or user_id, or — for
# message_attachments — is owned transitively via message_id → messages, so it
# must be scoped through a JOIN/subquery to messages):
#   mailbox_id-owned: messages, message_tags, tags, quarantined_messages,
#     contacts*, calendars, calendar_events, addressbooks, tasks, aliases, rules,
#     vacation_settings, read_receipts, folders, message_snooze, signatures,
#     drafts, mailboxes (the owning row itself).
#   user_id-owned:    user_spam_model, user_sender_list, user_smime_certs,
#     user_signatures, user_imap_settings, app_passwords, sessions.
#   message-transitive: message_attachments (message_id → messages.id).
UDT_RE='messages|message_tags|tags|quarantined_messages|mailboxes|contacts|contact_groups|contact_group_members|calendar_events|calendars|addressbooks|tasks|aliases|rules|vacation_settings|read_receipts|folders|message_snooze|signatures|drafts|user_spam_model|user_sender_list|user_smime_certs|user_signatures|user_imap_settings|message_attachments|app_passwords|sessions|jmap_changes_journal'

# ── Scoping tokens. A literal that names any of these is treated as carrying an
# ownership/scoping handle (positive pass) — but ONLY when the token appears in a
# PREDICATE context (a WHERE/JOIN/ON/AND/OR/HAVING/USING clause, or the WHERE of
# an UPDATE/DELETE), NOT in a SELECT projection / INSERT column list / VALUES /
# RETURNING (see predicate_context() below). The first four are the ownership
# currencies (ARCH-003: the account slot is a mailbox_id); the rest are
# FK-collection handles that are themselves mailbox-owned one hop away and are
# always resolved from the caller's session/mailbox before use.
TOKEN_RE='(^|[^a-z_])(mailbox_id|user_id|account_id|domain_id|tag_id|folder_id|calendar_id|addressbook_id)([^a-z0-9_]|$)'

# ── Allowlist: raw user-data queries that are LEGITIMATELY without a per-user
# scoping token. Each entry is `<basename> :: <unique lowercase substring>` and a
# REASON. The substring must appear (lowercased) in the comment-stripped literal.
# An entry only matches in its named file. Keep this list HONEST — every addition
# is a query a reviewer judged org-wide/admin/delivery/system, NOT a shortcut.
#
# Format per line (in the heredoc): <basename>\t<substring>\t<reason>
read -r -d '' ALLOWLIST <<'ALLOW' || true
admin_import_export.go	select mb.user_id, mb.domain_id from mailboxes mb where mb.id = $1	canReachMailbox authorization seam itself (2026-09-10 remediation round-6): the lookup RESOLVES the mailbox's owner/domain to feed admin_can_reach and the live admin_effective_authority domain-scope check — an ownership predicate is impossible by construction (owner unknown until this row returns); every downstream import/export action is gated on this result
admin_dmarc.go	from messages m join mailboxes mb on mb.id = m.mailbox_id	DMARC recent-failures report runs on workerPool; permission-gated, org-wide for global admins and constrained by mb.domain_id for domain-scoped admins
admin_ediscovery.go	select count(*) from messages m where %s	eDiscovery legal search — cross-mailbox by design, permission-gated admin console (ADR-006 carve-out)
admin_ediscovery.go	m.body_tsv @@ websearch_to_tsquery	eDiscovery full-text count — cross-mailbox legal search, admin-gated (plain GIN/tsquery, 2026-07-04 queue-B #2 revert)
admin_ediscovery.go	update messages set held = true	eDiscovery litigation hold over a legal-search result set, admin-gated
admin_ediscovery.go	select id, raw_ref, from_addr, subject, received_at from messages	eDiscovery export of a legal-search result set, admin-gated
admin_ediscovery.go	select distinct blob_sha256 from message_attachments where message_id = any($1)	eDiscovery object-lock legal hold over a legal-search result set — cross-mailbox by design, admin-gated (ADR-006 carve-out)
admin_ediscovery.go	update messages set held = false where id = any($1) and held = true	eDiscovery release of litigation hold over a legal-search result set, admin-gated (mirror of the set-held=true carve-out)
vcard_export.go	from contacts where addressbook_id = $1	CardDAV/contacts export helper — ownership enforced by the caller (addressBookID pre-verified to the requesting mailbox, R1/R3; see the ExportVCards docstring)
vcard_export.go	from contacts where id = $1	single-contact vCard export helper — caller-scoped (contactID pre-verified to the requesting mailbox, R1/R3; see the ExportVCard docstring)
admin_mailboxes.go	update mailboxes set display_name = coalesce($2, display_name)	admin mailbox edit — operates on the managed mailbox id; admin authority over every mailbox
admin_mailboxes.go	delete from mailboxes where id = $1	admin mailbox delete — admin authority over every mailbox
admin_monitor.go	select count(*) from messages where received_at	org-wide ingest counter (admin system monitor)
admin_monitor.go	select coalesce(sum(size_bytes),0) from messages	org-wide ingest-bytes counter (admin system monitor)
admin_quarantine.go	from quarantined_messages qm join messages m on m.id = qm.message_id where qm.id = $1	admin quarantine preview — admin authority; quarantine review console
admin_quarantine.go	delete from messages where id = $1	admin quarantine purge — admin authority
admin_quarantine.go	update quarantined_messages set released_at	admin quarantine release — cross-tenant admin surface (W7); org-wide requireMailPerm-gated, no per-user scope by design
admin_quarantine.go	update quarantined_messages set rejected_at	admin quarantine reject — cross-tenant admin surface (W7); org-wide requireMailPerm-gated, no per-user scope by design
caldav.go	select etag from calendar_events where id = any($1)	etag batch read over ids already resolved from a mailbox-scoped event query
itip.go	select organizer_email from calendar_events where uid = $1	iTIP organizer lookup by global event UID — cross-mailbox scheduling by design
calendar.go	select id from mailboxes where email = $1 and is_primary	delegate-RSVP manager-mailbox resolution; the reducer (p_on_behalf_of) gates on the delegate grant
handler.go	from mailboxes mb where mb.id = $1	own-mailbox purge-config read; $1 is the caller's identity.ResolvePrimaryMailbox result
handler.go	select jmap_email_state, jmap_mailbox_state, jmap_thread_state, jmap_tag_state from mailboxes where	state-token read; WHERE is appended in Go (id=$1 / user_id=$1 AND is_primary) from a server-resolved id
handler.go	select not exists (select 1 from messages where raw_ref = $1)	processOrphanedBlobs (blob GC worker, workerPool/BYPASSRLS): org-wide "is this raw_ref key still used by ANY message" recheck before deleting it from SeaweedFS; raw_ref dedup is content-addressed and global, not per-mailbox — there is no mailbox_id to scope by
ldap.go	from mailboxes where resource_type is not null	GAL resource-mailbox enumeration — org-wide directory (ADR-004: directory is org-wide, never domain-scoped)
search.go	from mailboxes where resource_type is not null	GAL resource-mailbox enumeration — org-wide directory (ADR-004)
search.go	from contacts where display_name ilike $1	GAL contact search — org-wide directory (ADR-004)
patch.go	update mailboxes set display_name = $1, updated_at = now() where id = $2	SCIM provisioning — system credential, authority over every mailbox
inbound.go	select 1 from aliases where email = lower($1)	inbound RCPT recipient-validity probe — delivery path; resolves whether an address exists org-wide
inbound.go	delete from message_tags where message_id = $1 and tag_id = $2	inbound delivery retag — system delivery path, cross-mailbox by design
inbound.go	insert into message_tags (message_id, received_at, tag_id, added_by) values ($1, now(), $2, 'system')	inbound delivery tag — system delivery path
quarantine.go	update messages set is_deleted = true where id = $1	user quarantine reject — ownership gated by the prior quarantined_messages mailbox-scoped check (TOCTOU noted in DATABASE_SECURITY.md R3)
rules.go	select exists(select 1 from mailboxes where id = $1)	admin rules console (requireAdmin): existence check; admin selects the target mailbox by design
rules.go	select eval_conditions(	rule dry-run; the message id was ownership-checked before this eval call
# ── Surfaced by the 2026-06-18 precision+coverage tightening (projection-only
# tokens no longer count; UDT_RE widened to tags/quarantined_messages/user_* /
# message_attachments/app_passwords/sessions). Each below was reviewed and is
# legitimately without a per-user WHERE predicate. THREE shapes recur:
#   (R2-INSERT) an INSERT into a per-user table sets its ownership column from an
#     AUTH/owned-resolved value in the VALUES list — an INSERT cannot carry a
#     WHERE; the token in the column list is correct, not scoping. (R2 set-from-
#     auth is reviewed at the call site; this guard does not verify it — residual.)
#   (ADMIN) a requireAdmin console query whose authority spans every mailbox.
#   (PRIOR-CHECK) a user query whose row was ownership-verified by an immediately
#     preceding mailbox-scoped check on the same id (TOCTOU noted, R3).
# ── (R2-INSERT) ownership column set from auth / owned-resolved handle ──────────
imap.go	insert into messages (mailbox_id, folder_id, imap_uid	R2-INSERT: IMAP APPEND sets mailbox_id from the session mailbox (c.mailboxID)
imap.go	insert into message_tags (message_id, received_at, tag_id, added_by, is_primary) values ($1, $2, $3, 'imap', true)	R2-INSERT: IMAP COPY attaches a destination membership whose message and tag were both resolved inside the session-scoped transaction; FORCE RLS is an additional backstop
imap.go	update mailboxes set used_bytes = used_bytes + $1 where id = $2	R2/session-scoped: A8 APPEND quota bump targets destMailbox, resolved from c.mailboxID / c.userID (the session's own mailbox), never cross-tenant
sync.go	insert into aliases (mailbox_id, email, domain_id) values ($1, $2, $3) on conflict	R2-INSERT: AD sync (ad/sync.go) sets mailbox_id from the synced mailbox; system credential
admin_users.go	insert into aliases (mailbox_id, email, domain_id) values ($1, $2, $3) returning id	R2-INSERT (admin): alias add sets mailbox_id from the admin-selected mailbox
admin_mailboxes.go	insert into mailboxes (user_id, domain_id, email, display_name, type, is_primary, quota_bytes)	R2-INSERT (admin): mailbox create sets user_id from the admin-selected user
admin_mailboxes.go	insert into folders (mailbox_id, parent_id, name, path)	R2-INSERT (admin): folder create sets mailbox_id from the admin-selected mailbox
rules.go	insert into rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule	R2-INSERT (admin rules console): mailbox_id set from the admin-selected mailbox (existence-checked first)
rules.go	insert into rules (mailbox_id, name, enabled, priority, run_on, conditions	R2-INSERT (admin rules console, template path): mailbox_id from the admin-selected mailbox
user_rules.go	insert into rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule	R2-INSERT (user /settings/rules): mailbox_id = caller's primary via ResolvePrimaryMailbox(auth); is_transport_rule forced FALSE (never a transport rule)
sender_list.go	insert into user_sender_list (user_id, sender, list_type) values ($1, $2, 'safe')	R2-INSERT: user_id set from u.UserID (auth); per-row replace under a prior DELETE WHERE user_id=$1
sender_list.go	insert into user_sender_list (user_id, sender, list_type) values ($1, $2, 'blocked')	R2-INSERT: user_id set from u.UserID (auth)
app_passwords.go	insert into app_passwords (user_id, name, label, token_hash) values ($1, $2, $3, $4)	R2-INSERT: user_id set from user.UserID (auth)
caldav.go	insert into calendars (mailbox_id, name, color) values ($1, $2, '#3b82f6')	R2-INSERT: mailbox_id resolved from user.UserID (caller's primary mailbox) just above
calendar_subscriptions.go	insert into calendars (mailbox_id, name, color) values ($1, $2, $3) returning id	R2-INSERT (WAVE-5 #10 webcal subscribe): mailbox_id resolved via identity.ResolvePrimaryMailbox(auth) just above, never the request body
vcf_import.go	insert into contacts ( addressbook_id, vcard_uid	R2-INSERT: addressbook_id is the job-scoped owned address book resolved by the migration orchestrator
ics_import.go	insert into calendar_events ( calendar_id, uid, component_type	R2-INSERT: calendar_id is the job-scoped owned calendar resolved by the migration orchestrator
inbound.go	insert into quarantined_messages (message_id, mailbox_id, original_tag, reason, reason_type, virus_name)	R2-INSERT: delivery path sets mailbox_id from the resolved recipient mailbox; system delivery path
# ── (ADMIN) requireAdmin console reads/writes spanning mailboxes by design ──────
admin_storage.go	left join message_attachments ma on ma.blob_sha256 = b.sha256	admin storage DR scan: org-wide blob ref_count reconciliation (requireAdmin)
admin_spam.go	coalesce(count(*), 0), coalesce(sum(sample_count), 0), coalesce(avg(sample_count), 0) from user_spam_model	admin spam dashboard: org-wide per-user-model rollup (requireAdmin)
admin_spam.go	coalesce(count(*), 0) from user_spam_model where disabled = true	admin spam dashboard: org-wide disabled-model count (requireAdmin)
admin_spam.go	from user_spam_model where trained_at	admin spam dashboard: org-wide recently-trained-model count (requireAdmin)
admin_spam.go	coalesce(sum(fp_count), 0), coalesce(sum(fn_count), 0), coalesce(sum(classified_count), 0) from user_spam_model	admin spam dashboard: org-wide accuracy rollup (requireAdmin)
admin_monitor.go	from quarantined_messages where released_at is null and rejected_at is null	admin monitor: org-wide pending-quarantine gauge (requireAdmin)
admin_monitor.go	from quarantined_messages where quarantined_at >= date_trunc('day'	admin monitor: org-wide quarantined-today counter (requireAdmin)
admin_monitor.go	from quarantined_messages where released_at is not null	admin monitor: org-wide released counter (requireAdmin)
admin_monitor.go	from quarantined_messages where virus_name is not null	admin monitor: org-wide top-virus rollup (requireAdmin)
admin_quarantine.go	from quarantined_messages where released_at is null and rejected_at is null	admin quarantine stats: org-wide pending counter (requireAdmin)
admin_quarantine.go	from quarantined_messages where released_at is not null	admin quarantine stats: org-wide released counter (requireAdmin)
admin_quarantine.go	from quarantined_messages where rejected_at is not null	admin quarantine stats: org-wide rejected counter (requireAdmin)
admin_mailboxes.go	select domain_id from mailboxes where id = $1	admin mailbox edit: domain lookup for the admin-selected mailbox (requireAdmin)
rules.go	from rules order by is_transport_rule desc, priority, id	admin rules console list (requireAdmin): lists all rules; admin authority by design
rules.go	from rules where id = $1	admin rules console get/eval by id (requireAdmin): admin authority over every rule
# ── (PRIOR-CHECK) user query gated by an immediately preceding ownership check ──
quarantine.go	update quarantined_messages set released_at = now(), released_by = $1 where id = $2 and released_at is null	user quarantine release — gated by the prior `qm.id=$1 AND mb.user_id=$2` mailbox-scoped check (TOCTOU, R3)
quarantine.go	select message_id, mailbox_id, original_tag from quarantined_messages where id = $1	user quarantine release follow-up read — same prior mailbox-scoped check (TOCTOU, R3)
mail_attach.go	select blob_sha256, coalesce(filename	PRIOR-CHECK: assembleAttachmentSubmission attachment list — the message was ownership-verified by the immediately-preceding read (WHERE id=$1 AND mailbox_id=$2)
# ADMIN e-discovery case binding — requireAdmin, case-scoped org-wide by design
admin_ediscovery.go	ediscovery_search_results (search_id, message_id)	shard3-007/V244 result binding: INSERT..SELECT binds the case's executed query rows; admin authority + case binding by design (search_id FK), not user-scoped
# ── (DELIVERY) system delivery path resolving a mailbox's owner ────────────────
inbound.go	select user_id from mailboxes where id = $1	delivery path: resolve the recipient mailbox's owner (mailbox id already resolved from RCPT); per-user spam scoping
inbound.go	select mailbox_id from messages where id = $1	condemnation in-tx follow-up (quarantineDeliveredTx): msgID is this connection's own INSERT..RETURNING in the SAME transaction - row identity established in-tx (R3 shape)
inbound.go	pg_xact_status(xmin::text::xid8) in ('in progress', 'subcommitted')	condemnation group fan-out: matches only copies this transaction just inserted (in-progress/subcommitted xact filter); delivery path
smime_harvest.go	select user_id from mailboxes where id = $1	S/MIME inbound harvest: resolve certificate owner from mailbox id (already resolved from RCPT); delivery path, same shape as inbound.go
# ── (DELIVERY) outbound worker — cross-mailbox by design (workerPool/BYPASSRLS) ─
outbound.go	from outbound_queue q left join messages m on m.id = q.message_pk	outbound drain worker: reads ALL pending queue rows across mailboxes; workerPool/BYPASSRLS cross-tenant delivery
outbound.go	from messages where message_id = $1 and smime_encrypt = true	S/MIME encrypt gate: message-level flag lookup; outbound worker is cross-mailbox (workerPool/BYPASSRLS)
ALLOW

fail=0
report() { echo "  $1"; fail=1; }

# predicate_context <lowercased-single-line-sql> → echoes ONLY the predicate
# portion of the statement (the text where an ownership token actually SCOPES
# rows), with the non-predicate regions blanked out so a token there cannot be
# mistaken for scoping. Removed regions:
#   · SELECT projection — everything between `select ` and the first ` from `
#     (a token in the SELECT column list is a leaked column, not a filter; this
#     is exactly the recall.go:56 shape — `SELECT … mailbox_id … FROM messages
#     WHERE id = $1`).
#   · INSERT column list — `insert into <tbl> ( … )` up to `values`/`select`.
#   · VALUES list — `values ( … )` (R2 territory: set from auth, not a filter).
#   · RETURNING clause — `returning …` to end (a returned column, not a filter).
# What survives is the WHERE / JOIN … ON / AND / OR / HAVING / USING predicate
# text. A token found there is genuine scoping. Implemented with awk gsub over
# the single-line lowercased SQL (portable BSD+GNU; non-greedy emulated by
# blanking the shortest projection span via index math).
predicate_context() {
  printf '%s' "$1" | awk '
    {
      s=$0
      # 1. blank the SELECT projection: from "select " to the first " from ".
      #    Loop to cover multiple SELECTs (subqueries/CTEs).
      while (match(s, /select /)) {
        head=substr(s,1,RSTART-1)
        rest=substr(s,RSTART+RLENGTH)
        fp=index(rest," from ")
        if (fp==0) { s=head " " rest; break }   # no FROM: drop the rest of "select"
        s=head " " substr(rest,fp)              # keep " from ..." , drop projection
      }
      # 2. blank a RETURNING clause to end of statement.
      rp=index(s," returning ")
      if (rp>0) s=substr(s,1,rp-1)
      # 3. blank a VALUES (...) list (its parenthesised group).
      vp=index(s," values ")
      if (vp>0) {
        pre=substr(s,1,vp-1); post=substr(s,vp+8)
        # drop up to the matching close paren of the first ( after values
        op=index(post,"(")
        if (op>0) { post=substr(post,op); depth=0; out=""; i=1; nn=length(post)
          while (i<=nn) { ch=substr(post,i,1)
            if (ch=="(") depth++
            else if (ch==")") { depth--; if (depth==0) { post=substr(post,i+1); break } }
            i++
          }
          if (i>nn) post=""
        }
        s=pre " " post
      }
      # 4. blank an INSERT column list: insert into <tbl> ( ... ) before values/select.
      ip=match(s, /insert into [a-z_]+ \(/)
      if (ip>0) {
        pre=substr(s,1,RSTART-1) substr(s,RSTART,RLENGTH-1)  # keep "insert into tbl "
        post=substr(s,RSTART+RLENGTH-1)                       # starts at "("
        depth=0; i=1; nn=length(post)
        while (i<=nn) { ch=substr(post,i,1)
          if (ch=="(") depth++
          else if (ch==")") { depth--; if (depth==0) { post=substr(post,i+1); break } }
          i++
        }
        if (i>nn) post=""
        s=pre " " post
      }
      print s
    }'
}

echo "==> ARCH-006 gateway per-user-ownership guard (positive)"

# allowlisted <basename> <lowercased-stripped-sql> → 0 if an entry matches.
is_allowlisted() {
  local base="$1" sql="$2" line akey asub
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    akey="${line%%	*}"                       # field 1 (basename)
    asub="${line#*	}"; asub="${asub%%	*}"   # field 2 (substring)
    [ "$akey" = "$base" ] || continue
    case "$sql" in *"$asub"*) return 0 ;; esac
  done <<< "$ALLOWLIST"
  return 1
}

# Extract every backtick SQL literal from the gateway tree (one record per
# literal, "FILE:STARTLINE<TAB>SQL", tabs/newlines collapsed to single spaces).
EXTRACT='
  BEGIN { inlit=0; buf=""; startline=0 }
  {
    line=$0; i=1; n=length(line)
    while (i<=n) {
      c=substr(line,i,1)
      if (inlit) { if (c=="`") { inlit=0; emit() } else { buf=buf c } ; i++ }
      else {
        if (c=="/" && substr(line,i+1,1)=="/") break
        if (c=="`") { inlit=1; buf=""; startline=NR; i++ } else i++
      }
    }
    if (inlit) buf=buf " "
  }
  function emit(   s) { s=buf; gsub(/[ \t\r\n]+/," ",s); sub(/^ /,"",s); print FILENAME ":" startline "\t" s }
'

# Iterate gateway Go files (skip tests), extracting every backtick SQL literal.
TMP_LITERALS="$(mktemp)"
trap 'rm -f "$TMP_LITERALS"' EXIT
grep -rlE '`' --include='*.go' "$GATEWAY" 2>/dev/null | grep -v '_test\.go' | while IFS= read -r gofile; do
  awk "$EXTRACT" "$gofile"
done > "$TMP_LITERALS"

while IFS=$'\t' read -r loc sql; do
  [ -z "$sql" ] && continue
  low="$(printf '%s' "$sql" | tr 'A-Z' 'a-z')"

  # Touches a user-data table? (FROM/JOIN/UPDATE/INSERT INTO/DELETE FROM <udt>)
  printf '%s' "$low" | grep -qE "(from|join|update|into|delete[ ]+from)[ ]+($UDT_RE)([^a-z0-9_(]|\$)" || continue

  # Skip reducer CALLS: a literal whose only verb is SELECT <fn>(…) or
  # SELECT … FROM <fn>(…) is a function call, not raw table access. We detect a
  # reducer call as "FROM <ident>(" or "select <ident>(" with NO bare FROM/JOIN
  # /UPDATE/INTO/DELETE on a real user-data TABLE (the udt match above already
  # required a table, so a literal that ALSO matches a reducer-call shape but has
  # a real table touch is treated as raw access — correct).
  # A pure reducer call (e.g. `SELECT deliver($1)`) never matched UDT_RE, so it
  # was already skipped by the continue above. Nothing more to do here.

  base="$(basename "${loc%%:*}")"

  # Positive: carries a scoping token IN A PREDICATE CONTEXT? A token that lives
  # only in the SELECT projection / INSERT column list / VALUES / RETURNING does
  # NOT scope rows — strip those regions first, then look for the token in what
  # remains (the WHERE/JOIN/ON/AND/HAVING predicate text).
  pred="$(predicate_context "$low")"
  if printf '%s' "$pred" | grep -qE "$TOKEN_RE"; then
    continue
  fi
  # Else must be allowlisted.
  if is_allowlisted "$base" "$low"; then
    continue
  fi
  report "[OWN] ${loc}  raw user-data query with NO ownership scoping token:"
  report "      $(printf '%s' "$sql" | cut -c1-140)"
  report "      → add a mailbox_id/user_id ownership predicate to the WHERE/JOIN, or (if genuinely org-wide/admin/delivery) add a REASON-commented allowlist entry in check-gateway-ownership.sh."
done < "$TMP_LITERALS"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "gateway per-user-ownership guard FAILED."
  echo "See docs/standards/DATABASE_SECURITY.md R4 and docs/adr/ARCH-006-app-level-isolation-posture.md."
  exit 1
fi

echo "    gateway per-user-ownership guard: clean."
