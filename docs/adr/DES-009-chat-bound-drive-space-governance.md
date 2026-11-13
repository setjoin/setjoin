# ADR: DES-009 — Chat-Bound Drive Spaces Are Governed, Not General-Purpose

**Status:** Accepted
**Date:** 2026-07-11
**Source:** `retired-docs:superpowers/plans/archive/2026-07-11-chat-A2-storage-on-drive.md` (chat A2); spec `retired-docs:superpowers/specs/2026-07-11-collaboration-suite-chat-conferencing-federation-design.md` §1.3/§2.4

## Context

Chat attachments (Pillar A2) land in a Drive space auto-provisioned per chat channel — the fix for Teams' worst storage flaw (1:1/group files live in the uploader's *personal* OneDrive → offboarding orphans them org-wide). setjoin lands every chat file, DM included, in an **org-governed** space from creation, with content-addressed dedup no competitor has.

The load-bearing implementation choice is **membership derivation**: rather than mirror channel members into `drive_space_members`, the single Drive membership choke point `drive_member_role(space, user)` gains an arm that reads `chat_channel_members` for chat-bound spaces (owner/admin → `manager`, member → `editor`). Every Drive RLS policy, reducer, and Go predicate routes through that one helper, so "file access = live channel membership" holds everywhere with zero sync.

But a chat-bound space is still, mechanically, a full Drive space — and the normal Drive verb-set (grant members, trash/rename/re-version nodes, an owner column with RLS powers) **re-creates the exact frozen-grant and evidence-destruction flaws A2 exists to eliminate**, and would let a member wedge the maintenance worker. The `/autoplan` review proved each of these against the shipped V114 code. So this ADR records that chat-bound spaces are deliberately **locked down** below the general Drive model.

## Decision

A chat-bound Drive space (`drive_spaces.chat_channel_id IS NOT NULL`) is governed, not general-purpose:

- **D1 — Membership is derived, never mirrored.** Access is a live function of channel membership at the one `drive_member_role` choke point. Removing a channel member instantly revokes file access; no frozen share survives.
- **D2 — No ad-hoc `drive_space_members` rows.** RLS + a BZ175 reducer belt reject explicit grants on chat-bound spaces, and the manager verbs (`member_grant`/`revoke`, `set_classification`/`policy`/`quota`) are gated to non-chat spaces. So "who can access = current channel members" is a **provable invariant** an A4 eDiscovery query can rely on — not a default a channel admin can quietly break by minting an invisible grant.
- **D3 — The owner column grants nothing.** `owner_user_id` is `NOT NULL` (schema constraint) and set to the channel creator, but the `drive_spaces_read` owner arm and the `drive_space_members_write` self-seed arm are guarded to `chat_channel_id IS NULL`. A removed creator keeps no residual read or re-grant power.
- **D4 — Attachment nodes are immutable via the Drive app.** Trash/move/rename/new-version on a node referenced by `chat_message_attachments` raises BZ175. A chat attachment is a point-in-time record, changed only through the chat message (soft-delete). This also keeps chat-attached nodes out of the trash→`destroy_hard` pipeline, whose un-handled FK would otherwise abort the maintenance sweep on every tick, forever.
- **D5 — Hidden from the Drive surface.** Chat-bound spaces do not appear in the `/drive` space list (user or admin); files are reached only through chat (attachment chip) plus a per-file read-context "Open in Drive" deep-link. Deleting a chat message revokes member access to its file (content route 404s) while retaining the bytes for A4 eDiscovery — deleted-for-members ≠ purged, matching the A1 body-retention posture.

## Consequences

- The marketed differentiators (org-owned-from-creation, live-membership access, content dedup) become **enforced invariants**, not documentation. A4's "who could access this file" and legal-hold stories inherit a clean guarantee.
- The cost: a chat-bound space is deliberately *not* a Drive workspace. You cannot share its files outside the channel, reorganize them, or edit them in Drive. That's intended — governance over flexibility for this space class. A future audited `drive.manage`-admin override (out of channel sharing, under audit) is a separate, later path if a real need appears; it is explicitly not A2.
- Reversing this (making chat spaces normal Drive spaces) would mean re-auditing every Drive read/write reducer and RLS policy for the chat-bound branch — this ADR exists so that cost, and the security reasons behind it, are understood before anyone proposes it.

## Alternatives rejected

- **Mirror channel members into `drive_space_members`:** sync writes in every chat-membership reducer, two tables that drift, a `granted_by NOT NULL` problem. Derivation is strictly better.
- **Allow admin grants + editor mutation (the Drive-native default):** rebuilds the Teams frozen-grant flaw, lets a member desync a chat record by trashing its file, and needs the worker-wedge FK handled separately. Rejected — it inverts the differentiator the pillar is sold on.
- **Message hard-delete reclaims space immediately:** destroys evidence at user-delete time, contradicting the compliance thesis (L2) and the A1 delete-retains-body decision. Reclamation is A4's legal-hold-aware purge.

## Extension — B2 recording (2026-07-15)

Meeting-bound Drive spaces (`drive_spaces.meeting_id IS NOT NULL`) are the second binding kind under the identical model — D1–D5 hold verbatim, one guard clause per site (`drive_member_grant`/`drive_node_{trash,move,rename}`/`drive_file_put_version`/`drive_spaces_read`/`drive_space_members_write`), no new predicate shape. The `drive_member_role` third arm derives `manager` (host/cohost, no `joined_at` required — their participant row is reducer-created) / `viewer` (an attended member) from `meeting_participants`, banned excluded, zero membership mirroring. The one deliberate difference from chat's audience: **audience is attendance, not membership** (D2 in the B2 spec) — a meeting has no durable roster the way a channel does, so "who can access a recording" is derived from the historical `meeting_attendee_role` read (host/cohost regardless of `joined_at`; a plain participant only with the webhook-fed attendance stamp), not a live "currently in the meeting" check, and NOT revoked by the meeting ending (D3's "hidden from `/drive`" and D4's "immutable via the Drive app" hold exactly as for chat). Full detail: `mailserver/internal/meet/AGENTS.md`'s "Recording (B2)" section; schema: `V129__meet_recording.sql` §C/§D.
