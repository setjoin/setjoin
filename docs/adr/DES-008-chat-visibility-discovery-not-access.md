# ADR: DES-008 — Chat Channel Visibility Controls Discovery, Never Content Access

**Status:** Accepted
**Date:** 2026-07-11
**Source:** `retired-docs:superpowers/plans/archive/2026-07-11-chat-A1-core-messaging.md` (grill session Q1); spec `retired-docs:superpowers/specs/2026-07-11-collaboration-suite-chat-conferencing-federation-design.md` §2

## Context

Chat channels (Pillar A1) need a discovery story — Slack/Teams/Mattermost all default to public channels a user can browse and join. But setjoin's entire chat authorization model — every reducer's guard, the `chat_member_role` SECURITY DEFINER helper, and the latent FORCE-RLS policies on `chat_channel_members` / `chat_messages` / `chat_message_revisions` — is built on ONE invariant: **reading a channel's content requires a membership row.** Slack additionally lets users *preview* a public channel's messages before joining; adopting that would put a `visibility = 'public'` escape hatch into every read path (reducers AND RLS policies), forking the single membership predicate into two.

## Decision

`chat_channels.visibility ∈ {public, private}` (DEFAULT `public`) controls **discovery and joining only**:

- **public** — listable by any org user via `chat_browse_channels` (name, topic, member count — never content) and self-joinable via `chat_channel_join`.
- **private** — invisible to non-members everywhere: browse omits it, and joining a private channel returns the SAME `BZ170` "channel not found" (HTTP 404) as a nonexistent id — enumeration parity, same anti-oracle posture as DES-003/booking's D3.
- **In both cases, content is readable only AFTER a membership row exists.** There is no preview. `visibility` appears in exactly two reducers (browse, join); every other read path keeps the single membership predicate.

DMs/group-DMs are structurally private (identity = exact member set; not browsable, not joinable).

## Consequences

- One membership predicate everywhere — reducers, the DEFINER helper, and RLS policies never branch on visibility; the native-RLS flip stays a no-op for chat.
- The cost: no Slack-style "peek before joining." A user must join a public channel to read it (join is one click and self-serve, so the friction is minimal; leave is equally one click).
- Revisiting this later (adding preview) means auditing every chat read reducer AND every chat RLS policy for a visibility branch — this ADR exists so that cost is understood before anyone re-proposes it casually.

## Alternatives rejected

- **Everything invite-only (no visibility column):** no `#general`, no organic adoption; retrofit = migration + predicate rework.
- **Public + open preview (Slack model):** best discovery UX, but forks the members-only read invariant across ~10 reducers and 3 RLS policies in the very first slice, and weakens the information-barrier story A4 builds on the same predicate.
