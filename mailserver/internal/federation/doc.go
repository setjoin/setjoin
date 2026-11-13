// Package federation is the Pillar C0 de-risking SPIKE for setjoin<->setjoin
// cross-org DM federation (Pillar C1's eventual production feature). It
// exists to prove — on a real 2-then-3 setjoin-instance harness — the risky
// mechanisms that gate committing to C1, NOT to ship a production feature:
// this package lives on branch pillar-c0-federation-spike and, per the
// plan's Task 6, does NOT merge to main as part of C0. See
// retired-docs:superpowers/plans/archive/2026-07-16-pillar-C0-federation-spike.md.
//
// Architecture: one long-lived, mutually cert-authenticated TLS s2s stream
// per peer domain, discovered via DNS SRV (_setjoin-im._tcp.<domain>,
// MX-shaped). Trust is a bilateral allow-list, default-OFF, mutual opt-in,
// per-domain scope (the Teams model) — the trust ANCHOR (a per-domain CA
// certificate, or a leaf SPKI pin as a C1 alternative) is pinned on the
// federation_allowlist row at allow-listing time, exchanged human-to-human,
// never auto-trusted and never derived from the wire itself. A peer is
// refused at handshake unless the local side has an enabled allow-list row
// for it AND the presented certificate validates against that row's pinned
// anchor (stream.go).
//
// DES-011 (docs/adr/DES-011-sfu-peripheral-reducers-are-authority.md)
// applies here unchanged: the s2s stream holds NO authority. It is a dumb
// transport — allow-list checks, ordering, dedup, archive, and delivery
// receipts are all reducer calls (mailserver/sql/reducers/federation_*.sql,
// landing in Task 2+). Nothing in this package decides whether a message is
// allowed to be delivered; it only carries bytes between two mutually
// authenticated domains once a reducer has already said yes.
//
// Why the outbound sender is its own mechanism, not the existing pushjobs
// worker: see the plan's "Why not pushjobs" section (pushjobs' 3-second,
// unordered-by-construction, per-row-backoff shape would fail E2's
// ordering/latency kill criterion for reasons that say nothing about
// federation's architecture — so the federation sender, landing in Task 2,
// is its own dedicated NOTIFY-woken, strictly-in-order-per-peer drain,
// reusing only the DB_DIRECT_DSN LISTEN/NOTIFY substrate
// (mailserver/internal/db/listen.go) pushjobs does not use).
//
// toggle.FeatureFederation is seeded OFF (D11); Dial/Listen both no-op
// (ErrFederationDisabled) while it is off.
//
// testharness/ holds spike-only scaffolding (per-domain test CAs, a stub
// DNS SRV server, a minimal fedharness daemon) — clearly non-production,
// never imported by cmd/mailserverd.
package federation
