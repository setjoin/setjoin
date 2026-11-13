# ADR: DES-012 — Hub-Relay Authority and Full-Stream Room Residency

**Status:** Accepted
**Date:** 2026-07-18
**Source:** `retired-docs:superpowers/plans/archive/2026-07-17-pillar-C2-rooms-presence-federation.md` (Design positions Q1/Q2, "Domain grill outcomes" 2026-07-17/18); C1's `federation_apply_chat` anti-spoof invariant (`retired-docs:superpowers/plans/archive/2026-07-17-pillar-C1-dm-federation.md`).

## Context

C1 (federated DMs) enforces one anti-spoof law on every inbound frame: `fromAddr`'s domain must equal the stream-authenticated peer (`stream.go`'s XEP-0178 handshake) — a peer can only ever assert authorship of its own users. That law is sufficient for a two-party DM: the stream peer and the message author's org are always the same org.

C2 (federated rooms) breaks that equivalence on purpose. A room is **hub-per-room**: N member orgs each hold one stream to a single hub org, never to each other. When the hub relays a member's message to the rest of the roster, the relay's stream peer is the **hub**, not the message's true author org — so the C1 law, applied verbatim, would poison every relayed message (`fromAddr`'s domain ≠ the relaying stream peer's domain). Something has to give: either rooms don't relay (defeating the point of a room), or the anti-spoof law bends for the one frame class where the hub is a trusted intermediary, not the author.

Separately, C1's residency posture ("each side archives only its own users, spec §4") assumed a DM's two archives are symmetric and complete. A room has no such symmetry: a member can be invited late, parked under backpressure, or have its scope revoked — so no honest claim of "every message, unconditionally" is available for a room the way it is for a DM.

## Decision

**(a) Hub-relay authority (Q2).** The hub may assert member-org authorship to the rest of the roster: `federation_apply_room`'s HUB side re-derives `fromAddr`'s domain against the **stream peer** (unchanged C1 law — a member can still only claim to be itself when talking to the hub), but the relay leg (`federation_room_fanout`) stamps `originDomain` from the hub's own validation, not from re-deriving anti-spoof per recipient. This is a deliberate, scoped **weakening** of C1's anti-spoof invariant for the relay leg only — the MUC / Slack-Connect posture, not a general trust-anyone rule.

The compensating control lives on the receiving spoke: `federation_apply_room`'s SPOKE side does **not** trust a relayed `originDomain` unconditionally. It requires the origin to be a member the spoke's own roster mirror (`federation_room_members`, hub-maintained via the `invite`/`roster`/`remove` control ops) currently lists as non-left, **or** the hub itself — `roster ∪ {hub}`. An origin outside that set poisons. The one deliberate carve-out is the `room_revoked` advisory (F2): it names the hub itself as origin (never a third party) and exists precisely to inform a peer whose own roster entry was just withdrawn, so it cannot be checked against a roster that no longer includes the recipient's own up-to-date state — the advisory's authorize-skip is keyed on the op, not a blanket relaxation.

**Without this ADR, a future agent will "fix" the anti-spoof back** — re-deriving `fromAddr`'s domain against the stream peer on the relay leg too, "for consistency with C1." That silently poisons every relayed message in every room, permanently. This is the load-bearing consequence to check before touching `federation_apply_room`'s HUB-side or `federation_room_fanout`'s origin-stamping.

**(b) Full-stream room residency (Q1).** Every member org archives **every ACCEPTED message while ACTIVELY RECEIVING** (join-forward from its own `invited_at`; parking and no-backfill mean an unconditional "full stream" claim is false, so it is never made — per-member coverage gaps are recorded in `federation_room_members.coverage_epochs` and disclosed in the eDiscovery export manifest, Task 8). The hub holds **the hub's record of messages it accepted and relayed** — messages poisoned or scope-refused at ingest never entered it, so "authoritative relay record" is always stated with that qualification, never bare.

This deliberately **supersedes spec §4's "each side archives only its own users"** for rooms — federated DMs are unaffected (C1's model stands there: each side is symmetric and complete by construction, since a DM has exactly two parties and no relay). **No cross-org deletion propagation in v1**: *a remote tombstone must never override another org's legal hold; if cross-org deletion propagation ever comes, it is a preserved deletion REQUEST/event — each org decides the lawfulness of physical purge.*

## Status

Accepted. Cross-ref: `mailserver/internal/admin/admin_chat_ediscovery_export.go`'s per-member coverage-facts manifest section (Task 8 Step 1) states this residency claim in its export-facing wording; the 记录留存 (records-retention) legal sign-off gate — standing since C0, a precondition before `feature.federation` flips ON anywhere — now explicitly covers this hub-holds-room-history + every-member-archives-while-actively-receiving posture.

## Consequences

- Every future room-relay code change must preserve the split: HUB-side anti-spoof re-derives against the stream peer (unchanged C1 law, protects the hub from a lying member); SPOKE-side trust is bounded to `roster ∪ {hub}` (protects a member from a rogue or compromised third party the hub might otherwise vouch for). Weakening either side independently reopens either the relay (if HUB-side is tightened back to C1's law) or the spoke's trust boundary (if the roster∪hub check is dropped).
- The residency claim is a per-member, coverage-qualified claim, never an unconditional one. Any manifest, marketing, or compliance text that drops the "while actively receiving" / "accepted and relayed" qualifiers overstates what the system actually proves and must be corrected, not just the code.
- No org can weaponize deletion against another org's legal hold — a real cross-org purge feature, if ever built, is scoped as a request/event each receiving org adjudicates locally, never an automatic remote-triggered destroy.

## Alternatives rejected

- **Full mesh (every member org streams directly to every other member org):** avoids the hub-trust question entirely, but requires O(n²) bilateral allow-list pairs per room and loses the single choke point (`federation_room_enqueue_member`) the Q9 park/revoke/warn discipline depends on. Rejected as needless complexity for a self-hosted 300–10,000-user org's actual room sizes.
- **Keep C1's per-frame anti-spoof unconditionally, even on the relay leg:** structurally impossible without abandoning relay — the hub IS the stream peer for every relayed frame, so re-deriving `fromAddr`'s domain against the stream peer on that leg always fails for a non-hub author. Rejected: this is the exact trap the ADR exists to name and forbid re-introducing.
- **Trust the hub's asserted `originDomain` on the spoke with no compensating check:** unchecked trust with no floor — a compromised or buggy hub could attribute a message to any domain, including one never in the room. Rejected in favor of the `roster ∪ {hub}` check, which costs nothing extra (the roster mirror is already maintained for membership display) and closes the gap.
- **Unqualified "full stream" / "authoritative" residency wording:** the grill's first pass used this phrasing; it is falsified by parking and the no-backfill posture (a parked-then-resumed member has a real gap). Rejected in favor of the qualified wording this ADR states verbatim, carried into the export manifest and CONTEXT.md.
