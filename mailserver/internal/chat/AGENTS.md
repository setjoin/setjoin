# mailserver/internal/chat — Chat/IM Pillars A1–A4b (DOX child)

Owns Chat translation; reducers, Drive and UI retain authority. Handler.registerRoutes owns routes. Use claims.UserID and membership, not primary mailbox; requests use dbscope.RunUserScoped and FORCE-RLS proofs. Mutations serialize channel-row sequence assignment; replay includes edits/tombstones. Soft deletion hides content, not compliance evidence. Attachments belong in live-membership chat-bound Drive spaces, not personal space or send-time grants. Public discovery grants no content access. Read seq/membership contracts; attachments require DES-009, visibility DES-008, receipts DES-010. Query/RLS changes require DATABASE_SECURITY and ARCH-018. Read relevant compliance/guest/federation sections before changes.

## DOX sections

- [Purpose](DOX.md#purpose)
- [Ownership](DOX.md#ownership)
- [Architecture — membership-scoped, not mailbox-scoped](DOX.md#architecture--membership-scoped-not-mailbox-scoped)
- [The seq rail (the load-bearing invariant)](DOX.md#the-seq-rail-the-load-bearing-invariant)
- [Feature surface (A3 QoL) — one-line contracts](DOX.md#feature-surface-a3-qol--one-line-contracts)
- [BZ160–178 map (`errors.go`)](DOX.md#bz160178-map-errorsgo)
- [Attachments (A2) — files live in a chat-bound Drive space, never a personal one](DOX.md#attachments-a2--files-live-in-a-chat-bound-drive-space-never-a-personal-one)
- [Push seam + `notify_decouple` recommendation + fan-out ceiling](DOX.md#push-seam--notify_decouple-recommendation--fan-out-ceiling)
- [Presence — deliberately not reducer-backed](DOX.md#presence--deliberately-not-reducer-backed)
- [DES-008 — discovery-not-access invariant](DOX.md#des-008--discovery-not-access-invariant)
- [Mobile push (A3.5) — server-side `notif_level`/DND enforcement at push time](DOX.md#mobile-push-a35--server-side-notif_leveldnd-enforcement-at-push-time)
- [A1/A2/A3/A3.5 deferrals (owners, not vague "later")](DOX.md#a1a2a3a35-deferrals-owners-not-vague-later)
- [Records lifecycle (A4a) — audit chain, retention, legal hold, purge, gxp/WORM channels](DOX.md#records-lifecycle-a4a--audit-chain-retention-legal-hold-purge-gxpworm-channels)
  - [NOT in scope (A4a) — carried forward, not silently dropped](DOX.md#not-in-scope-a4a--carried-forward-not-silently-dropped)
- [Oversight (A4b) — eDiscovery reader/export + durable case holds](DOX.md#oversight-a4b--ediscovery-readerexport--durable-case-holds)
  - [Deferred (A4b) — carried, not dropped (each with its seam)](DOX.md#deferred-a4b--carried-not-dropped-each-with-its-seam)
- [Federated rooms (C2) — the cross-org surface (DM + rooms), `feature.federation`](DOX.md#federated-rooms-c2--the-cross-org-surface-dm--rooms-featurefederation)
- [Guest doors (G0–G3) — the constrained-external-user surface, `feature.guest_accounts`](DOX.md#guest-doors-g0g3--the-constrained-external-user-surface-featureguest_accounts)
