# CONTEXT.md — setjoin domain language

The project's ubiquitous-language glossary. Skills (`/improve-codebase-architecture`, `/to-prd`, `/triage`) read this to name things the way the team does. Use these terms exactly; avoid the listed alternatives. ADRs live in `docs/adr/`.

## Product name

The platform's official names are **setjoin** (English, /ˈsɛt dʒɔɪn/) and **集合** (Chinese, *Jí Hé* — 集 gather/collect/set + 合 join/unite). Company and product share the name. Primary domain: **setjoin.com** (no `.cn` — the product is self-hosted, ICP filing is the customer's).

The reverse domain **`com.setjoin`** is **frozen**: it is the root prefix every client identifier derives from — iOS/Android bundle IDs & package names (`com.setjoin.mail`, `com.setjoin.guard`), the iOS Keychain access group (`com.setjoin.shared`) and App Group (`group.com.setjoin.shared`), the JMAP capability URN prefix (`urn:setjoin:`), and the deep-link scheme (`setjoin://`). These are embedded in App Store records, Keychain, APNs topics, and installer GUIDs — changing them after first release forces an uninstall/reinstall (local cache loss).

- _Avoid_: the superseded codenames **Prism** (2025 dev codename), **Lumio** / **聚办**, and **Atlumio** / `atlumio.com` / `com.atlumio` (all retired 2026-05-31).

## ScheduledAction

A unit of work with a **deferred execution time** (`fire_at`) and a **declared kind** (`action_kind`), dispatched by a polling cron and run by a **kind-specific handler**. The thing modeled is *intent deferred to a future moment*, not a clock.

- _Avoid_: **timer** (a mechanism, not the thing modeled), **job** (overloaded), **cron entry**.
- Table: `scheduled_actions`. Audit trail: `scheduled_action_log` (append-only).
- Kinds (extensible, additive): `send` (scheduled + undo), `snooze`, `remind`, `dsn` (the bounce Delivery Status Notification — WAVE 9 relocated it out of the synchronous `outbound_queue` AFTER UPDATE trigger into this infra; `action_kind` has no CHECK so a new kind needs no column migration); future `ooo_toggle`, `digest`, `retention_sweep`.
- The **dispatcher** routes by `action_kind` and never inspects `payload`; **handlers** own their own failure contract and never inspect each other's payloads.
- Exactly-once: optimistic claim (`UPDATE … WHERE status='pending' RETURNING`) + `locked_until` for crash recovery + a per-kind dedup key for egress kinds.
- Spec: `retired-docs:superpowers/specs/2026-06-16-scheduled-actions-design.md`. Supersedes the "timer" framing in architecture-review candidate #3 / Track A6.

## Channel (chat)

A named, persistent chat conversation space with explicit **membership**. Two visibilities: **public** (discoverable by any org user — name/topic/member-count listable — and self-joinable; the default) and **private** (invite-only, undiscoverable). **Membership gates reading in all cases** — there is no "preview without joining"; visibility controls *discovery and joining*, never *content access*. A **DM / group DM** is a special channel whose identity *is* its exact member set (same set ⇒ same conversation; member set immutable).

- _Avoid_: **room** (Matrix connotation), **conversation** as the storage term (UI word only), **group** (collides with distribution groups).

## Chat-bound space

A **Drive space auto-provisioned per [[Channel (chat)]]** to hold that channel's file attachments (org-governed, never a personal space — the fix for Teams' orphan-on-offboarding flaw). Its membership is **derived** from the channel's membership (not mirrored), so file access follows channel membership live. It is a **governed, not a general-purpose, space**: no ad-hoc member grants, the owner column grants nothing, and its file nodes are **immutable via the Drive app** (a chat attachment is a point-in-time record, changed only through the chat message). Hidden from the Drive space list — reached only through chat. See [ADR DES-009](docs/adr/DES-009-chat-bound-drive-space-governance.md).

- _Avoid_: **channel folder** (it is a full space, not a folder), **shared drive** (M365 term with different semantics).

## Federated DM

A [[Channel (chat)]] `kind='dm'` row **bound to a peer org's domain and one remote identity** (`federated_peer_domain` + `federated_remote_id`): the local user is the channel's **sole member**; the remote party is **identity metadata, never a local account, member, or directory row** (no ghost users — the §4A "Model 1" posture). Inbound federated messages carry `author_id NULL` + `federated_sender_addr` (honest attribution for eDiscovery/retention: the record says who at which org, not a fake local user). Which orgs may federate at all is the **bilateral allow-list** (`federation_allowlist`, default-off, mutual opt-in, anchor-pinned per XEP-0178); delivery over the wire is exactly-once on a per-peer seq rail; the transport ack doubles as the XEP-0184 delivered tick.

- _Avoid_: **guest DM** (a guest is a provisioned local constraint, a federated party is never local), **external contact** (implies a directory row; federation deliberately creates none).

## Federated room

A [[Channel (chat)]] `kind='channel'` row spanning **N member orgs** on the **hub-per-room relay model**: exactly one org — the **hub** — owns the room's real channel and streams to every other member; every other member org holds a **spoke mirror** (its own local channel, live-mirrored, never a read-only cache). Distinct from [[Federated DM]] (two parties, no relay, no hub) — a room's `roomId` is `<uuid>@<hub domain>`, globally unique and self-describing. **Parked** describes a member the hub has stopped enqueueing to (backpressure only, when its unacked outbox backlog crosses the org-configured cap) — still a valid message origin, not removed. **Revoked** describes a member whose room-scope allow-list entry was withdrawn — a visible state, not a silent parking: the member leaves the roster and its mirror goes read-only with a banner, never a quiet loss. Residency (ADR [DES-012](docs/adr/DES-012-hub-relay-authority-and-room-residency.md)): each member org archives every message it accepted **while actively receiving** (join-forward from invite; parking and re-invite gaps are recorded, never silently dropped or backfilled) — the hub additionally holds the hub's record of every message it accepted and relayed. **Federated typing** (never "presence") rides the room the same way: ephemeral, non-attributed signals with no identity beyond room-scope routing, unarchived and excluded from 会话存档/eDiscovery by design — a distinct, lesser claim than presence (online/offline status), which C2 does not federate.

Disambiguate from **Meet's SFU room** ([ADR DES-011](docs/adr/DES-011-sfu-peripheral-reducers-are-authority.md)): that "room" is a LiveKit media session, unrelated to chat or federation. Also distinguish the **roster** (`federation_room_members`, ORG-level — which member organizations are in the room) from the **chat member list** (`chat_channel_members`, USER-level — which local users at each org can read that org's copy of the room).

- _Avoid_: **presence** for federated typing (product/compliance name is "federated typing" — no online/offline status crosses orgs), **anonymous** for typing frames (they are *non-attributed*: no identity is carried in the payload, but origin org + timing can still narrow who in a small room is typing), **room** alone without "federated"/"Meet SFU" qualifier (ambiguous between the two senses above), **full stream** / **authoritative** without the "while actively receiving" / "accepted and relayed" qualifier (falsified by parking + no-backfill — see DES-012).

## Pin (chat)

A **channel-scoped curation act**: an authorized member elevating a message to channel-official status. A pin is an **org record** — it travels with the [[Channel (chat)]] in compliance exports, and pinning/unpinning are auditable acts. Unpinning is **collective** (any authorized member may unpin anyone's pin — curation belongs to the channel, not the pinner).

- _Avoid_: **bookmark**, **favorite** (those are personal — see [[Saved message (chat)]]).

## Saved message (chat)

A **personal bookmark** on a chat message, visible only to the saving user. A save is a **user record** — it never appears in channel exports and carries no organizational meaning; it surfaces only in user-scoped discovery.

- _Avoid_: **pin** (a pin is an org-visible curation act — see [[Pin (chat)]]), **star** (legacy mail term).

## Org-default channel

A [[Channel (chat)]] every org member belongs to **by policy**. Membership is **system-maintained** — auto-joined at provisioning, backfilled when a channel is marked org-default — and **non-revocable by the member**: muting, not leaving, is the escape valve (the Slack #general / Teams org-wide / DingTalk 企业群 posture). Unmarking makes the channel ordinary again; existing memberships persist. The only exits: unmark the channel, or deactivate the user.

- _Avoid_: **mandatory channel** (membership is mandatory; reading is not), **broadcast channel** (that's a posting-permission concept, orthogonal).

## Meeting

A real-time media session (scheduled or ad-hoc) bound 1:1 to an SFU room, and optionally to a [[Channel (chat)]] for its text lane (a huddle binds the *origin* channel; a scheduled meeting gets a bound channel that **persists after the meeting ends** — meeting chat is a compliance record, not ephemera). Meetings are **org-open by design**: any authenticated org user may join or knock at an unlocked meeting (the Teams intra-org model); `locked` and the guest double-opt-in are the barriers. A meeting **ends**; it is never deleted — the row and its participant records persist.

- _Avoid_: **call** (UI word for the huddle affordance only), **room** (that's the SFU-side object a meeting is bound to, never the domain term).

## Knock (meeting)

A join **request** from someone without direct entry: always for a guest; for a member only when the meeting is locked. The **poll is the completion contract** (admitted → token; denied/expired → terminal) — pushes are a latency bonus, never the contract, so a knocker can never dead-end.

- _Avoid_: **lobby** as the request itself (the lobby is the host-side queue surface; the knock is the request).

## Meeting guest

A name-only, single-meeting external participant: media + reactions tier, **no chat** (guests have no user row; forging guest authorship into chat would poison the retention/eDiscovery rails). Double-opt-in (org `meet.guest_access` AND per-meeting `guestAllowed`); admitted through a [[Knock (meeting)]]; revocation is server-side **eviction**, never token expiry (see [ADR DES-011](docs/adr/DES-011-sfu-peripheral-reducers-are-authority.md)). Distinct from the future **guest account** (a provisioned constrained user) and from **federation** (org↔org).

- _Avoid_: **external user** (that's the guest-account concept), **anonymous** (display name is required and badged).

## Guest account

A **constrained external user inside our tenant**: a real, mailbox-less `users` row plus a `guest_accounts` satellite (invited by email, local credentials, time-boxed, profile-constrained, fail-closed). One of THREE external models — distinct from [[Meeting guest]] (model ③, ephemeral name-only) and from **federation** (model ①, org↔org). Members see guests badged **"External" / 外部** on every people surface (user-ratified 2026-07-18); the Meet lobby's 访客 wording stays reserved for meeting guests. A guest's authored content is archived/eDiscoverable exactly like a member's (real `author_id`); the guest accepts an archival/monitoring disclosure at invite-accept. Spec: `retired-docs:superpowers/specs/2026-07-18-guest-accounts-design.md`.

- _Avoid_: **guest** unqualified in UI copy (collides with the Meet lobby's 访客); **guest user** for model ③ (that's a [[Meeting guest]]).

## Reducer

A PL/pgSQL function in `mailserver/sql/reducers/` that holds business logic ("logic where the data is"). The Go gateway is a thin protocol translator that calls reducers. Mutating reducers bump `jmap_*_state` in-transaction and `pg_notify`.
- _Avoid_: "service", "stored proc" (it's the architecture's load-bearing unit, not an incidental DB detail).

## Location / Snooze tag groups

`message_tags` enforces two **exclusive groups**: `location` ∈ {Inbox, Sent, Drafts, Trash, Spam} and `snooze` ∈ {Snoozed, Scheduled}. Archive = remove the `location` tag; All Mail = no Trash/Spam tag. A snooze is **two facts**: a `snooze`-group tag *and* a `ScheduledAction` (kind `snooze`) — two rows, two tables.

- **A folder is a tag, not a mailbox; `messages.mailbox_id` is immutable.** What IMAP/JMAP call a "folder" (Inbox/Sent/a custom label) is a `tags` row (`imap_expose=TRUE`); selecting/moving between folders is a `message_tags` swap (`transition_message_location`, `jmap_email` mailboxIds) — it **never** changes `messages.mailbox_id`. The `mailbox_id` is set at delivery and fixed for life: it is the **mailstore = tenant unit** (the RLS/ADR-003 currency), *not* the folder. So folder navigation is an **application predicate** (`tag_id`); the **security principal** (`mailbox_id`) is a separate, immutable axis. This is why a single immutable `mailbox_id` is the right RLS key and why `message_tags` (which has no `mailbox_id` column) derives its tenant from the underlying *message*, not its tag.

## Account scope (`parseAccountID`) / `p_mailbox_id`

The gateway resolves a JMAP `accountId` to the authenticated user's **own** mailbox and forbids cross-account access at that boundary. **`parseAccountID` returns the user's PRIMARY MAILBOX id, not their `users.id`** — and validates `accountId == (SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary)`. So a reducer's `p_account_id` **is a `mailbox_id`**. `mailboxes.id` and `mailboxes.user_id` are independent sequences that diverge for shared/resource/SCIM mailboxes; they only coincide for the very first user.

- **Canonical name: `p_mailbox_id`** (decided in [ADR-003](docs/adr/ARCH-003-account-scope-currency.md); `p_account_id` is retired). The account-slot argument is **always a `mailbox_id`** — one currency, no exceptions. Reducer ownership joins scope by the mailbox: `mailboxes.id = p_mailbox_id` (or `mailbox_id = p_mailbox_id`), **NEVER `mailboxes.user_id = p_…`**. A `user_id = <mailbox arg>` predicate is a type-confusion bug: in production it matches zero rows, silently breaking the feature (RSVP fails, the GAL returns empty, a destroy reports success but leaves the row).
- **Need the user or domain behind a mailbox? Call the resolver `account_scope(p_mailbox_id) → (mailbox_id, user_id, domain_id)`** — never hand-join `mailboxes` to derive them (it re-introduces the confusion and the `user_id IS NULL` shared-mailbox edge). `account_scope` owns that mapping in one tested place.
- **`p_viewer_id` is a different concept, not a different currency.** The shared-calendar *viewer* (`jmap_calendar_*_get_shared`) is keyed on the authenticated person (a `users.id`) because "who is looking" is genuinely not "which mailbox". It keeps a distinct name so it reads as deliberate. `send_read_receipt`, formerly user-keyed, **converts to `p_mailbox_id`** and resolves the sender via `account_scope` — so on **mailbox-domain** reducers the only user-keyed parameter is `p_viewer_id`. (Genuinely **user-scoped domains** — approvals per ARCH-012-approval, Drive spaces — key on `p_user_id` / the `app.current_user_id` RLS principal by design; that is a different domain, not a relaxation of this rule.) *(Until the ADR-003 rename wave runs — sequenced after the Track-A feature work — legacy `p_account_id` and the old `send_read_receipt` signature may still appear in the tree; the rule above is the target the rename converges on.)*
- **Rule (do not relax): shared calendar reducers get a new `getShared` path keyed off the authenticated viewer; `parseAccountID`'s same-mailbox guard is never relaxed.** Sharing is additive — an explicit ACL-checked read path — never a loosening of the identity guard. The wire term stays: `parseAccountID` and the Go `accountID` var keep their names (`accountId` is the correct JMAP word); the rename is only at the reducer seam.
- **pgTAP fixtures MUST use divergent `user_id != mailbox_id`** — create accounts via the `mk_account(label) → mailbox_id` / `mk_shared_mailbox(...)` helpers (disjoint id ranges), never hand-rolled coincident ids. Coincident ids mask this exact confusion class — a buggy `user_id = <mailbox arg>` predicate passes by accident. A suite **grep guard** fails on any such predicate (outside the `p_viewer_id` exception) and on any new `p_account_id` reducer parameter — the invariant is self-enforcing, not just documented.
- _Avoid_: "just pass the other user's `accountId`" — that's the exact bug the same-mailbox guard prevents; and "scope ownership by `user_id = <the mailbox arg>`" — that's the reducer-side version of the same confusion.

## Directory scope / identity resolution

A setjoin **deployment is one organization** (each client gets its own deployment; setjoin is **not** multi-tenant). **Domains and AD forests are mail-routing + AD-sync boundaries within the one org, not tenant boundaries.** So the directory/GAL is **org-wide** — `directory_tree`/`directory_members`/`directory_search`/`gal_search` span the whole deployment; scoping any of them by the caller's home `domain_id` is a bug that fragments one org.

A directory entry is a **person**: one identity with a **full address set** (`users.email` ∪ `aliases.email` ∪ `ad_upn`). A single **`resolve_identity(address) → person`** seam (lookup by any of those) is the matching key for the directory/GAL (search + return all addresses), federated login in **SP mode** (match an external IdP's assertion subject/UPN/alias before JIT-provisioning — never just the primary email), and mail (already alias-aware). **IdP mode** asserts the canonical person.
- **Resolve by the handle you have; never hand-roll the match.** A rule keyed on an **address** (the only handle is an email/UPN — e.g. a bounce's `from_addr`) resolves through **`resolve_identity`**; a rule keyed on a **mailbox or a message** (the handle is a `mailbox_id`, or a `message_id` that joins to one — e.g. a read-receipt's governing reader) resolves through **`account_scope`**, which never touches an address and is therefore alias-proof by construction. A raw `lower(addr)` match inside a rule is a **new twin of the predicate** — forbidden. Picking the wrong resolver (address-matching when you actually hold a mailbox, or vice-versa) re-introduces the alias-miss bug class ADR-004 fixed. Both resolvers carry the canonicalizer's boundary — `shared/identity.CanonicalizeAddress` (trim + **ASCII-fold** lower + RFC-5322 display-name strip; never rejects, so bare UPN/Kerberos principals pass through to match `ad_upn`). Every Go match site (`resolveUserByAddress`, the local/AD connectors) normalizes its input through it; the paired provision site uses `NormalizeAndValidate` (= `CanonicalizeAddress` + `validate.ValidateEmail`), and on success `NormalizeAndValidate(x) == CanonicalizeAddress(x)` so match-key == provision-key by construction (closes the duplicate-JIT-on-normalization bug). The stored rows are canonicalized writer-first by migration **V089** (collision-detecting, aborts loudly on two rows that fold together — never auto-merges). The **stored** fold is NOT the full input canonicalizer: a stored value (users.email, aliases.email, users.ad_upn) never carries a display-name wrapper (email columns are ASCII-CHECK'd; ad_upn is a raw UPN/Kerberos principal), so V089's permanent `fold_stored_address(text)` is **trim + ASCII-A-Z fold ONLY** — **no** display-name strip (input-only; a blind `<...>` extract would have collapsed `host/server.corp@REALM <x@y>` → `x@y`, silent data loss on ad_upn) and **no** `lower()` (would fold `İ`→`i` and disagree with Go's asciiFoldLower). Its trim **mirrors Go's `strings.TrimSpace`/`unicode.IsSpace` set exactly** — an explicit `U&'…'` cutset of all 25 whitespace codepoints (U+0009,000A,000B,000C,000D,0020,0085,00A0,1680,2000–200A,2028,2029,202F,205F,3000), NOT default `btrim` (whose default cutset omits TAB/LF — a real writer-vs-matcher drift on ad_upn). `fold_stored_address` is the guarded SQL twin of the display-strip-free half of `CanonicalizeAddress`, pinned by `shared/identity.TestFoldStoredAddress_MatchesGo` (DB-gated byte-equality over a no-display-name corpus that carries every whitespace axis as leading+trailing affixes); the prod deploy-gate audit flags any row where `x <> fold_stored_address(x)`. **No Unicode/IDN** folding until a future writer-first migration extends this same seam.
- _Avoid_: treating a domain as a tenant; scoping the GAL by `u.domain_id`; matching a federated identity by primary email only (duplicates the user). See [ADR-004](docs/adr/ARCH-004-directory-org-scope.md).

## Dispatch privilege boundary (the cron worker's connection)

The ScheduledAction dispatcher and the outbound-queue drain run as **plain `plpgsql` reducers with no `SECURITY DEFINER` / `BYPASSRLS`** — they rely entirely on the **Go cron worker's privileged connection** for the access they need (same model as `drain_outbound_queue`, V068). **That connection IS the intentional privilege boundary for all dispatch operations.** Keeping the reducers definer-less means there is no privilege-escalation surface and the dispatch path is immediately legible.
- _Do not_ "fix" a dispatch reducer by adding `SECURITY DEFINER` to make a test pass or to grant it RLS bypass — that silently moves the privilege boundary off the worker connection and into the function body. If a test needs dispatcher privileges, run it through the worker connection, not by elevating the reducer. See `retired-docs:superpowers/specs/2026-06-16-scheduled-actions-design.md` §3.
- **Native-RLS amendment (decided 2026-06-19, native-rls-backstop B2):** when native RLS lands, the legitimately-cross-mailbox paths (the dispatcher, `deliver()`/inbound MTA delivery, journaling, admin reads) bypass FORCE'd RLS via a **dedicated `BYPASSRLS` *role*** that those connections use — **still the connection, not the reducer body**, as the boundary. The definer-less rule above is preserved: the escape is a role on the worker/delivery/admin *connection*, never a `SECURITY DEFINER` reducer. **Both SMTP paths run on the BYPASSRLS (worker) role** — corrected by the W4 audit (2026-06-20). *Delivery* (inbound `:25`) is cross-tenant by nature: `deliver()` resolves the recipient **server-side** and writes into THAT mailbox. *Submission* (`:587`, and JMAP `EmailSubmission/set`) is **also** cross-tenant: `send()` does local-recipient delivery — it calls `deliver()` into OTHER mailboxes (the option-1 fan-out), which a sender-pinned tenant GUC cannot satisfy (the WITH CHECK on the recipient row would deny it, 42501). The earlier "submission = tenant-scoped, runs on the app role under the tenant wrapper" framing was wrong: submission self-authenticates at the SMTP AUTH layer and `send()` self-authorizes the sender (send-as/delegation gates) *before* any write, so it needs no tenant GUC. send()/deliver() already explicitly scope every user-data read by the auth-resolved mailbox (R1/R4), so dropping the RLS backstop on the bypass pool opens no hole inside them. See `retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md` (W4).

## User-parameterized bypass (the recall risk class)

Existing bypass paths (dispatcher, `deliver()`, journaling, admin reads) are all **system/worker-triggered with a scope the user does not control** — the connection runs only trusted tasks, so "the connection is trusted" is sufficient. **Recall is different: it is the first end-user-driven action that writes mailboxes the caller doesn't own, parameterized by user input (the message to recall).** That is a distinct, higher-risk class. For it, "the connection is privileged" is *not* enough — the authorization must be **internalized into the write predicate** so the statement is structurally incapable of overreach, not gated by a skippable/raceable pre-check. Concretely: the bypass `UPDATE`/reducer pins its `WHERE` to the **authenticated sender's identity** (recall touches only copies of a message the caller provably sent — a sent copy exists in `p_recaller_mailbox_id`), so even on the BYPASSRLS connection, even if the Go pre-gate is bypassed or has a TOCTOU, the write can only reach "messages I sent." Cross-tenant writes stay on the **visible** BYPASSRLS role (never smuggled onto the tenant-facing app pool by setting a foreign GUC — that is impersonation, which RLS does *not* catch: RLS verifies scope-consistency, never the authorization to choose that scope). Audit is **forensics, not control**; prefer a soft/recoverable effect (recall → Trash tag + a visible stub) over a silent hard delete.
- _Avoid_: treating a user-parameterized bypass like a worker bypass ("the connection is trusted, so the raw cross-mailbox `UPDATE` is fine"); relying on an app-code pre-check as the sole gate when the write itself could be reached another way; "impersonating" each recipient by setting the app-role GUC to a foreign mailbox to make the write look RLS-policed. See `retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md` fork 4.

## Send failure classification

A send attempt fails either **transient** (retry) or **permanent** (terminal, no retry). The distinction is load-bearing and must live in an **explicit, named classifier with tests** — never ad-hoc inference, or it drifts. Examples: SMTP **421** / connection timeout → transient; SMTP **550** (bad recipient) / a `BZ` validation error → permanent. See `retired-docs:superpowers/specs/2026-06-16-scheduled-actions-design.md` §5.
- _Avoid_: treating all failures as retryable (double-sends) or all as terminal (drops a recoverable send).

## Sound guard vs cheap guard

A guard must hold in the ways that *matter*, not merely pass "better than nothing." For each guard, ask precisely what bypasses it — and where the **sound** form costs about the same as the **cheap** form, take the sound one:
- a **grep** misses variable-laundered writes (`x := u.UPN; bind(x)`), a newly-added address-like field, and query-builder paths → a **compile-time newtype** (only `CanonicalizeAddress` mints a `CanonicalAddress`; a raw string fails to *compile* at every write site, enumerated or not) cannot be bypassed.
- a **count-floor** passes a *partial* load where one reducer silently fails above the floor → assert **expected-set ⊆ actual** (the manifest exists: it's the `reducers/*.sql` function names).
- a **golden-capture** test that asserts what the code *emits* passes by construction and catches nothing → anchor the oracle to the **external spec** (the RFC clause + a citing comment) so it fails on drift-*from-spec*, not merely on output-change. (The author-fiat-test class: V089 corpus, the calendar byte-proof. The scope-agreement `mintedScope` USED to be in this class — its oracle was a hand-copied fiction of the mint query — but is now single-sourced through `shared/permissions.MintDomainScope` (the issuer's real code path), so deleting the mint's `expires_at` clause turns it red; the cure for that class is to make the oracle *be* the code under test, not a copy of it.)
- _Avoid_: shipping the cheap form where the sound form is available at similar cost — it builds a layer that *looks* like enforcement but is bypassable exactly where it matters (partial load, laundered write, code-drift-that-isn't-a-change). Generalizes ARCH-006's positive-guard posture.
- _Sequencing is part of the decision, not just the "what."_ A guard/fix with an ordering dependency (e.g. an input-canonical-vs-*stored* match that's only safe *after* the writer/backfill is canonical) must state *when* it lands, or it trades one bug for another on the path nobody's watching.

## State invariant vs transition invariant

A data rule is either a property of **one row's state** — true of the row in isolation (e.g. `used_bytes ≥ 0`, an enum membership, a NOT-NULL pair) — or a property of a **transition between states** — only meaningful across a change (e.g. `used_bytes ≤ quota_bytes`, which an admin legitimately violates by *lowering* a quota under current usage, and which reconciliation overwrites). A `CHECK` constraint enforces only the former: it fires on every row unconditionally, so pointing it at a transition rule rejects legitimate states. **State invariants → `CHECK` (free, un-bypassable). Transition invariants → the reducer/trigger that owns the transition.** Floors and non-negativity are state invariants (take the CHECK); ceilings and quotas are transition invariants (keep them in the reducer that already guards the increment).
- _Avoid_: "add a CHECK for every invariant" — a ceiling CHECK rejects the admin-oversubscribe and reconciliation-overwrite states that are legitimately over the line. Ask first: am I protecting one row's state, or a transition? Only the first is a CHECK.

## Schema artifact vs schema authority

The database is **one shared cluster** (ARCH-002) with **one connected FK graph** — `users` is co-owned (mailserver creates it, `authserver/sql/schema/007_users_extend.sql` ALTERs it), authserver tables FK-reference it, and mailserver migrations reference authserver tables. So the **schema artifact** is unavoidably unified: one dependency-ordered baseline (a curated `pg_dump`, CREATE-all-then-ADD-FK because the graph has cycles) + one forward chain. **But schema *authority* — who reviews/owns a change to a given table — is a separate, org-level fact the FK graph cannot disprove** (auth tables FK-referencing `users` does NOT mean the mailserver maintainer understands OIDC `sub`-mapping). The principle: **only merge what reality forces, and only split what reality forces.** The FK graph forces merging the artifact; *nothing* forces merging authority — but splitting authority is itself **precondition-gated: it pays only when there are genuinely two owners with distinct domains + release cadences.** With multiple teams → keep auth-domain forward migrations under the auth team (per-module forward dir + `CODEOWNERS`; boundary tables like `users` get co-owners; timestamp versions to avoid a two-team renumber tax). **For a SOLO maintainer (this deployment, decided 2026-06-18) artifact and authority coincide → one baseline, one forward chain, one owner; the split would be unnecessary ceremony.** Re-split the moment a separate auth team/owner forms.
- _The same move as predicate-vs-projection._ Merging a shared artifact must not silently transfer ownership of its parts — but neither should you split ownership that has only one owner.
- _Avoid_: "one baseline ⇒ one tree owns all migrations" (smuggles authority into an artifact decision); paying the per-module-authority cost (CODEOWNERS, split dirs, timestamp versions) when there is only one maintainer.

## Upgrade intent, execution, and recovery evidence

An **upgrade intent** is the authenticated, audited request an authorized administrator creates from the Admin Portal: select an approved release, accept its declared effects, and ask the host to begin. It is **not** permission for the gateway to replace its own binary. **Upgrade execution** belongs to a separate root-owned `setjoin-updater` coordinator outside the gateway process. The coordinator verifies the approved release, persists progress across process and host restarts, controls service lifecycle and schema sequencing, evaluates health gates, and commits or rolls back the executable deployment. The Admin Portal and gateway may authorize, enqueue, observe, and cancel only at declared safe boundaries; they never copy installed binaries, invoke arbitrary shell commands, or own systemd/root credentials.
- _Artifact/startup invariant_: transport downloads only missing signed artifact digests, but the updater materializes and atomically activates a complete immutable compatibility group. System startup may resume or trigger an already-approved transaction; only `setjoin-updater` may use the distinct owner credential to apply migrations before starting business processes. Gateway/auth processes only read-check their declared schema/contract range and fail closed; they never auto-migrate.
- _Dependency-coordination invariant_: one signed Release Manifest v2 is the transaction root for Core plus PostgreSQL/PgBouncer, SeaweedFS and optional Collabora. Managed installs accept only receipted platform digests, reuse an installed accepted build unless compatibility/security/format policy requires movement, and checkpoint compatibility groups behind whole-release admission. Customer-managed dependencies are inspect-only; the first implementation accepts PostgreSQL only on the local host.
- **Recovery point created** means the application-level database dump, blob/config manifest, and required protected-config evidence completed their declared integrity checks. It does not mean a restore has been proven.
- **Restore proven** records a separate, bounded isolated restore drill and its evidence timestamp. The UI must not collapse it into "backup succeeded."
- **Platform snapshot** means an external Proxmox/VMware/cloud or host LVM/ZFS/Btrfs snapshot. Unless an explicit provider integration can query and validate its state, Setjoin records only operator attestation and never claims the snapshot is verified.
- _Authority invariant_: compromising the tenant-facing gateway must not grant a general root command surface. The updater accepts only a closed, versioned upgrade-intent schema over a local authenticated transport and resolves artifacts from an approved release manifest rather than caller-supplied filesystem paths.
- _Avoid_: self-modifying gateway handlers; treating an HTTP 200 from a binary copy as a completed upgrade; exposing script/path arguments through the web API; or calling an inaccessible hypervisor snapshot "verified."

## Community and Enterprise release channels

**Community** and **Enterprise** are promotion and assurance channels over one forward-only signed build lineage, not separate customer-data formats or long-lived forks. Community receives a current build first after its required automated gates; Enterprise receives the same lineage after its additional integration, real-environment and soak gates, with signed offline delivery, certified upgrade/recovery evidence and accountable support. Ordinary fixes and features move forward without routine old-build backports or an Enterprise LTS branch; critical security fixes are never intentionally withheld from Community and may use a declared fast-track. Every artifact remains immutable and identifiable by build ID, source commit, digest, schema/API levels and compatibility manifest. Normal production rollout targets 14–30 days with 90 days as the maximum supported drift; older builds keep running but may need signed bridge checkpoints. An administrator requests the latest approved build once, and the updater chooses a direct same-epoch path or the minimum automatic bridge path across contract/irreversible boundaries. On-premise administrators schedule feature-update maintenance rather than receiving silent forced updates. Switching eligibility never requires reinstalling or migrating customer content. Entitlement expiry must never stop mail delivery, login, ordinary data access, export, or restore, and never delete customer data.
- _Avoid_: using authentication JWT signing keys for commercial entitlement; making Community artifacts unsigned; remotely disabling an expired on-premise deployment; or treating the channel name as permission to bypass manifest compatibility rules.

## KeySet / signing keystore (token signing currency)

First-party tokens (access/refresh/MFA/reset/impersonation) are signed through **one seam** — `JWTProvider.sign()` — and verified through **one seam** — `JWTProvider.Validate()`. The signing key is **asymmetric (ES256, P-256)**, held in a **DB-backed encrypted keystore** (`signing_keys`: kid, alg, public_jwk, private_key_enc, status ∈ active/retiring/retired), and the public keys are published by `kid` in a **first-party JWKS** the resource server (the mailserver gateway) verifies against — **no shared secret**. A `kid` binds to exactly one `alg` (RFC 8725); the gateway trusts only the configured JWKS URL (no `jku`/`x5u`). The **`KeySet`** module owns generate/load, the active signer, the kid→public-key verifier map, JWKS marshaling, and rotation.
- _The migration invariant_: the gateway **dual-verifies** (HS256 legacy secret **and** ES256 via JWKS) during rollout; issuance flips to ES256 only after the gateway can verify it; HS256 acceptance is removed only after one access-token lifetime drains. Never a flag day.
- _Avoid_: giving a resource server the symmetric `JWT_SECRET` so it can verify (that hands it minting power); matching a token by a public key used as an HMAC secret (alg confusion); trusting a `kid`/`jku` from the token header. See [ADR-005](docs/adr/ARCH-005-asymmetric-jwt-jwks.md).

## Latent vs live defect

A defect reachable only through a **transient or unreachable path** — a route A→B transition window, an unwired frame, a branch no user action hits — is **latent**, not **live**. Name it as latent: it still justifies a fix (it bites the moment the path becomes reachable, or it blocks dependent work), but **not** with the urgency of a defect users hit today. **Verify reachability before claiming a "live bug"**: are the colliding consumers actually mounted at the same instant? does the frame render? does any action reach the branch? (The webmail push singleton's inbox↔calendar callback-drop is real but **latent** — the split-view dock is an unwired M2 frame, so inbox is the sole live push registrant; the collision is reachable only on a route transition. The fix — a multi-listener hub — is still required, as Phase 0 of `wire-task-contact-push-reactivity`, because it unblocks Task/Contact consumers and closes the transition window.)
- _Avoid_: overclaiming urgency ("a live two-pane bug") for a latent collision — it costs reviewer trust, and the honest justification (unblocks dependent work + closes a transition window) is load-bearing on its own.

## Layered containment for untrusted HTML

Rendering untrusted email HTML (a reading pane, a quarantine preview) needs **three independent layers**, each covering the others' blind spots: **markup** — client `sanitizeHTML` (DOMPurify) strips scripts/handlers/`javascript:`; **scripts** — the iframe `sandbox=""` (with `srcdoc`, never a navigable `src`) contains anything sanitize missed; **resources** — a CSP (`default-src 'none'`) blocks resource loads (incl. CSS-triggered fetches). Close the directives that **don't** fall back to `default-src` — `base-uri`, `form-action` — explicitly; and know the delivery gotcha: a `<meta>`/srcdoc CSP silently *ignores* `frame-ancestors`/`sandbox`/`report-uri` (deliver via a response **header** when the content is served from an endpoint; for an inline `srcdoc`, `<meta>` is forced and `frame-ancestors` is a parent-page concern instead). Blocking `data:` images is a **decoder-surface / don't-render-the-lure** call, not a beacon one (`data:` issues no request). A single barrier that is **silently the sole defense on a routine action** is fragile; layer it, and **pin each layer** (a dropped `sandbox` or a `srcdoc`→`src` swap renders identically and fails only on a malicious message — exactly what grep/review miss). **Quarantine is suspected-malicious mail**, so its preview must also block **resource loads**: `sandbox=""` stops scripts but not `<img src>`, and sanitizers keep images by default, so opening a quarantined phish auto-fires its **tracking beacons** (confirming a live, monitored address) — only the resource layer (CSP) closes that, and the XSS framing alone misses it. Quarantine **stores raw bytes** (forensic fidelity) and **sanitizes at render**, never mutating stored content server-side; the "see the exact payload" need is met by **escaped text in a `<pre>`**, not a raw render (text shows the real `<script>`, encoding tricks, true URLs a render hides). A server-side tag **blocklist** that string-replaces is **false safety** — *delete* it (don't trust it; don't replace it with a server sanitizer that corrupts the record). **But when the thing you're tightening (a render, an endpoint) is *also* the de-facto byte/inspection path, the inspection need does not vanish with it** — verify a replacement exists (a download, or an inert escaped-text view), or **bank one in the same change**; never delete the only byte path on an unverified "loses nothing." That vacuum is exactly what gets filled later by someone re-adding the unsafe path, re-opening the hole you closed. (Sanitizing the admin quarantine render removed the sole way to see raw bytes → bank an escaped-text "view source" in the same PR; the full `.eml` download is the forensic upgrade.)
- _Avoid_: one barrier doing silent double duty; trusting a server tag-blocklist; adding an unsanitized *render* path for "forensics" when escaped text is safer and more useful; deleting a render/endpoint that doubles as the byte path without confirming or banking a replacement; applying quarantine's resource-blocking CSP to normal mail (legitimate newsletters carry remote images — that's a separate user "block remote images" setting).

## Measured duplication vs assumed duplication

Before extracting a "shared" abstraction from N call sites, **measure the actual overlap** — don't trust a "~70% is copy-pasted" eyeball. Count the **byte-identical** surface vs the divergent bodies. *One* instance is not a pattern (*one adapter = a hypothetical seam*); superficially-similar code with divergent bodies (different form fields, a two-phase save, array validation) yields a **shallow** factory that *moves* complexity into per-call callbacks rather than concentrating it — failing the deletion test. Extract only the surface that is genuinely identical, at the layer where it actually repeats (often the components, not the already-thin stores). (The PIM "collection-store factory": claimed ~70% shared lifecycle; measured ~12 identical lines, everything else intrinsically divergent → [ADR-009](docs/adr/ARCH-009-no-pim-collection-store-factory.md), no factory.)
- _Avoid_: DRY-ing on a narrative ("these three look the same") instead of a measurement; pointing the abstraction at the wrong layer (a "store factory" when the stores are already thin and the repeat lives in the components).

---

## Architecture vocabulary (for deepening reviews)

- **Module** = interface + implementation. **Interface** = everything a caller must know. **Depth** = much behaviour behind a small interface (good). **Shallow** = interface ≈ implementation (bad). **Seam** = where an interface lives. **Adapter** = a concrete thing satisfying a seam. **Locality** = change/bugs/knowledge concentrated in one place.
- **Deletion test**: if a module vanished, does complexity disappear (pass-through) or reappear across N callers (earns its keep)?

## Drive — space, node capability, classification, chunk/manifest, export grant (2026-08-03)

- **Space** — Drive's storage, policy, audit, and isolation unit. Existing membership (`manager`/`editor`/`viewer`) is the ordinary-space root/default grant source; node capabilities may narrow or extend access below it. RLS keys on the **user principal** `app.current_user_id` (the ARCH-012-approval precedent — Drive data is user-scoped, not mailbox-scoped, so the ADR-003 `p_mailbox_id` currency does not apply).
- **Node capability / grant / inheritance break** — a capability is one typed action fact (`traverse`, `list_children`, `read_metadata`, `preview`, `download`, `create_child`, `modify_content`, `rename`, `move`, `delete`, `manage_acl`, or `view_audit`). A grant binds a stable Setjoin user/group principal to a node with `self|children|subtree` propagation and optional time/use bounds. An inheritance break stops ordinary inherited grants; node-local grants and the minimum traverse-only ancestor projection still apply. There is no arbitrary ordered deny rule in the first release.
- **Path-only ancestor** — a node synthesized with `traverse` only so a principal can reach a deeper grant. It reveals that exact ancestor's identity/name but never permits sibling enumeration. “Can traverse A/B to C” does not mean “can list A or B.”
- **Effective access** — the database-owned intersection of source/binding eligibility, root/direct/group grants and inheritance, node/operation preconditions, classification/export/retention/WORM policy, and Guest/app/device entitlement. An outer policy may narrow but never widen a grant. Web/native capability projection is an affordance; reducers remain authoritative.
- **Classification** is ONE monotonic axis: `regular → secure → gxp`, upgrade-only, never downgraded. Not three independent knobs. "Secure space" = classification `secure` (client-side SQLCipher vault sync, in-app render only, no plaintext on endpoint disk). "**Compliance mode**" / "gxp space" = classification `gxp` = everything `secure` implies PLUS WORM/Object-Lock, retention, approval-gated export/share, audit-all. `feature.drive` gates Drive; `feature.drive_compliance` gates only creating/upgrading to `gxp`.
- **Node / version / manifest / chunk** — a node is a tree entry (folder or file); a file's history is a metadata-only version DAG (concurrent writes yield a **conflict sibling**, never last-writer-wins); a version's bytes are an ordered **manifest** of content-addressed **chunks** (fixed 4 MiB in v1). **Dedup scope**: regular spaces share one global pool (`'g'`); secure/gxp chunks are per-space (`'s<space_id>'`) — no cross-boundary existence signal.
- **Export grant** — a single-use, TTL'd, token-hash record minted only by policy short-circuit or approval-apply; the ONLY path by which bytes leave a secure/gxp space (download/print).
- **Approval-as-e-signature** — the Part-11 e-signature record IS the existing `approval_requests` row plus the space's chained audit rows; no new signature mechanism. Product copy says **"Part-11-CAPABLE"**, never "compliant" (customer runs IQ/OQ/PQ).
- **Scope-containment for mirror tokens** — a native-client token minted with a non-empty `Scp` (the Drive P1 native-token bridge) is a **mirror credential** for the one HTTP surface it names, never a full-session credential. REST applies **path-prefix** containment (`chain.AuthenticateRequest` — reject unless the request path is under `/`+`Scp`); the WS/SSE **push** channels **blanket-reject** any non-empty `Scp` (no push surface is scoped). Both go through a **named acceptance seam** (`AuthenticateRequest` / `AuthenticatePushToken`), never a leaked `JWT().Validate()` — the push seam also holds the `Type==access` guard, so a refresh token can't open a stream. Machine-checked by `scripts/check-scope-containment.sh` + `TestAuthenticatePushToken_Guards`.
- _Avoid_: treating space membership as a bypass around node capabilities; treating `traverse` as list/read authority; using email/UPN/DN/display name as an ACL principal; “WORM space” as a synonym for gxp (WORM is one gxp control among several); calling the server store a “vault” (the **vault** is the client-side SQLCipher store keyed per ARCH-016 Model M; the server side is chunks + manifests).
- Drive side-panels own their own server read (self-fetch, e.g. MembersSheet/FolderAdminsSheet); DriveApp owns layout + routing, not panel state.

## Chat records lifecycle — retention ceiling vs WORM floor, legal hold, chain notary (Chat A4a, 2026-07-13)

- **Retention (chat)** is the SAME field name (`chat_channels.retention_days`)
  meaning **two opposite things** depending on [[Channel (chat)]] classification —
  never conflate them in copy or code comments. On a **regular** channel it is a
  **destroy ceiling**: the nightly purge sweep permanently deletes messages
  older than it. On a **gxp** channel it is a **WORM keep-floor**: messages
  are immutable (cannot be edited or deleted) for at least that long, and the
  purge sweep never touches the channel at all. "Retain for N days" / 保留 N
  天 / 保存期限 is banned as a REGULAR-channel label — the CN compliance
  reading of 保存期限 is a mandatory floor, the exact opposite of a destroy
  ceiling, and this mistranslation destroys customer data.
- **gxp channel (chat)** = a [[Channel (chat)]] upgraded (never downgraded)
  to WORM/compliance classification — the chat sibling of Drive's
  `classification='gxp'`. Never rendered as "gxp" in any UI string (a pharma
  term inherited from Drive); the product word is "Records (WORM)" / 合规存证
  （不可篡改）.
- **Legal hold (chat) beats retention/WORM by construction** — a BEFORE
  DELETE trigger (`trg_chat_message_hold`), not a query predicate that could
  be forgotten in one read path. The single-homed predicate `chat_hold_active`
  is the only thing the trigger, the purge sweep, and the admin channel list
  ever call — since A4b it has TWO arms: the A4a per-channel boolean and
  active [[Case hold (chat)]] coverage. **One matter per channel** is the
  BOOLEAN arm's law only: a second, different matter cannot be set on an
  already-held channel (rejected, not silently overwritten); a release is
  **reason-scoped** (releasing one matter can never drop another). Case
  holds layer freely — many cases may hold one channel as separate rows.
  A held channel must be **invisible as held to the custodians it targets**
  (tipping-off) — the audit chain, `legalHold` state, and case-hold state
  are never projected to an end user, only to compliance admins.
- **Chain-head notary** — a single row a nightly audit-chain anchor writes to
  a SEPARATE, already-append-only HMAC chain (`admin_audit_log`), recording
  the CURRENT head `(id, checksum)` of every per-conversation chain it just
  digested. A pure hash chain detects forgery/edits/mid-chain deletion but
  not a contiguous TAIL truncation (the surviving prefix still verifies) —
  the notary closes exactly that gap: the next anchor refuses to re-anchor a
  channel whose live head is below/differs from its notarized floor, and a
  verifier reports it as truncation, never a silent pass.
- **`destroyedElems`** — the per-id digest elements (`id:author_id:epoch:
  sha256(original_body)`) a purge act carries for every record it destroys,
  so an audit-chain verifier can RECONCILE an anchor spanning a lawfully
  purged range to a hard TRUE instead of excusing a permanent mismatch (the
  "was a purge involved?" escape hatch this design deliberately does NOT
  have — that would make lawful destruction and tampering indistinguishable).
  It proves WHICH records were destroyed; it never lets anyone reconstruct
  destroyed content, and it cannot prove a negative ("this record was never
  destroyed") about content that never existed.
- _Avoid_: "retain for N days" as a regular-channel label (see above);
  "gxp" in any user-facing string; a hold-visibility exception for the
  custodian "so they know why they can't delete something" (tipping-off);
  a purge "excuse" field instead of a reconciling digest.

## Chat oversight — case hold, record floor, the read/destroy SoD split (Chat A4b, 2026-07-15)

- **Case hold (chat)** — a durable hold row (`chat_case_holds`) belonging to
  exactly ONE `ediscovery_cases` matter, scoped to a custodian (user) or a
  channel. Coverage is **materialized** (memberships ∪ channels the
  custodian ever authored in — pre-hold departures covered), **grown** by a
  join trigger, and **NEVER pruned on leave** (leave-can't-expose: a
  custodian leaving a channel must not lift its protection). Release is
  case-scoped by construction — a hold row belongs to one case, so releasing
  it can never drop another case's coverage (the reason-string workaround the
  boolean arm needed is dissolved).
- **Record floor** — the honest framing of `last_purged_seq` + the purge
  acts' id-ranges on every eDiscovery reader/export surface: "this channel's
  record begins above a purge floor." Never a replayable cursor (`seq` is
  re-stamped on edit), and never a negative proof — the record proves what
  the `destroyedElems` leaves say and nothing more; it cannot prove a
  specific held message was NOT destroyed. The disclaimer sentence is
  verbatim in console i18n AND the export manifest.
- **The read/destroy SoD split** — `chat.ediscovery` (search/read/export
  every employee's chat — the most privileged read in the product) is its
  own sensitive permission, deliberately NOT fused into
  `chat.compliance_manage` ("may destroy" ≠ "may read") and NOT granted via
  `compliance.write` (which would silently grant chat-content read to every
  existing holder the day the toggle flips).
- _Avoid_: presenting `last_purged_seq` as a cursor; any "proves X was not
  destroyed" claim; a member-read policy on any hold/oversight table (the
  tables are FORCE-RLS deny-all — tipping-off); reusing `compliance.write`
  for chat-content read.

## Offline vault / biometric unlock (ARCH-016, 2026-07-08)
- **Offline vault key** — the random 32-byte key that encrypts the local SQLCipher mail cache. Held WRAPPED in the OS keystore/TPM (Model M), NOT derived from a user passphrase. Distinct from the account password.
- **Account password / login** — the credential (or WebAuthn/Kerberos-SSO) that authenticates to the mail SERVER. Governed by authserver + the existing self-service `forgot_password.go`. Unrelated to the offline vault key.
- **Device-unlock tier** — offline key released automatically while the OS user is logged in / device unlocked (Outlook-style, default, no prompt).
- **Biometric app-lock tier** — offline key gated behind a biometric gesture (opt-in; `feature.biometric_unlock`).
- **Vault passphrase** — DEPRECATED; Model M has no user passphrase anywhere on the client. guard-core's `self.key` (the single key behind TOTP seeds, the ECDH push key, AND the offline store key) is now **born random and held wrapped in the OS keystore** (`new_with_keystore()`), not derived from a passphrase. An optional passphrase tier is a future add for zero-knowledge customers, not the default.
