# ADR: DES-010 — Chat Read Receipts Are Watermarks, Not a Fact Table

**Status:** Accepted
**Date:** 2026-07-12
**Source:** `retired-docs:superpowers/plans/archive/2026-07-12-chat-A3-qol.md` (grill session Q1); spec §2.3 (watermark rationale)

## Context

Read receipts (已读) are a signature CN-market chat feature — DingTalk shows per-message read/unread **name lists**, and buyers in a WeCom/DingTalk bake-off expect them. The naive model is a read **fact table**: one row per (message, reader) with a timestamp. At org scale that is O(members × messages) write amplification — a 500-member channel turns every scroll-through into 500-row fan-in per screen of messages, which is precisely the load pattern that degrades DingTalk at scale and would swamp the per-channel `change_seq` write path A1 built.

A1 already ships per-member **watermarks**: `chat_channel_members.last_read_seq`, one row per member per channel, advanced monotonically by `chat_mark_read`.

## Decision

**The watermark is the only read-state record.** "Read by" is always a *derivation*: a member has read message `m` iff `last_read_seq >= m.seq`.

- A3 adds a projection (`chat_channel_readers`) and UI over the existing watermarks — no new write path, no per-message rows.
- **Live fan-out is DM-only** (`member_read` events; 2 members, bounded). Channels refetch watermarks on open/focus/own-send — no O(members²) read-event noise in big channels.
- **Names are visible, not just counts** (tap "read by N" → member list): the watermark rows are member-readable under RLS regardless, so a names-hidden UI would be a curtain, not a guarantee (same reasoning as the per-voter-visible poll posture).
- **No per-user opt-out, ever** — 已读 is org-governed workplace state in a compliance product. A deferred **org-level** `chat.read_receipts` kill switch (default ON) is registered for works-council jurisdictions; when it lands, the UI degrades to nothing.

## Consequences

- Read state is O(members) per channel, independent of message volume — the write path scales to 10k-seat orgs by construction.
- **Per-message read history is unrecoverable by design.** "Exactly when did user X read message m" is never captured — only "X has read up to seq S as of its last advance." A future request for DingTalk-style per-message read *timestamps* is not a UI task; it requires a new fact table capturing data the watermark model deliberately discards, plus its own retention/purge treatment in the compliance pipeline. This ADR exists so that cost is understood before anyone re-proposes it casually.
- A watermark can only advance; "mark unread" (rewinding) would un-read *everything after* the target message, not one message. That is the correct semantic under this model and should be presented as such in any future mark-unread UI.

## Alternatives rejected

- **Read fact table (one row per message×reader):** exact per-message timestamps, but O(members × messages) writes — the DingTalk-scale trap the spec's watermark design exists to avoid; also a compliance-pipeline surface (billions of rows under retention).
- **Count-only display (Teams "Seen by N"):** softer optics, but the underlying rows are member-readable via RLS anyway; hiding names in the UI is a false privacy promise.
- **Per-user opt-out (mail's V081 MDN gate):** wrong consent domain — MDN privacy protects users from *external senders*; 已读 is intra-org accountability state. A per-user opt-out guts the feature (DingTalk offers none); jurisdictional concerns are org-level, hence the deferred org toggle.
