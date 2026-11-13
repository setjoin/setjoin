# ADR: ARCH-028 — Rust replaces Go; PL/pgSQL reducers stay where they save round trips

**Status:** Accepted; supersedes the "remove database-resident reducers in version 1" target and
ARCH-026's rejection of Rust calling a reducer
**Date:** 2026-10-29
**Authority:** owner decision 2026-10-29 (after the #217 Rust-vs-Go measurement); spec
setjoin/setjoin#209; amends [ARCH-026](ARCH-026-per-command-rust-authority-transfer.md)

## Context

The rewrite target of 2026-10-11 moved business logic out of PL/pgSQL reducers into Rust
commands in version 1. The first transfer (mark-read, #214) reimplemented
`jmap_email_set_update` as 14 separate statements. Measured against the Go path on the same
host (`retired-docs:verification/2026-10-29-rp07-rust-vs-go-mark-read.md`), it was about 2.5x slower
at p50 and used 2-3x the database CPU: every statement crossed the network and was planned
from scratch, while the reducer runs as one call whose inner statements PL/pgSQL plans once
per session. The cost is the data-access shape, not the language.

## Decision

1. **Rust replaces Go as the protocol and orchestration layer.** The end state is still no
   Go server (ARCH-027 front door, routes leave Go one at a time).
2. **Reducers stay, from version 1, wherever they save round trips.** A Rust command whose
   work is a multi-statement transaction calls the existing reducer in one statement
   instead of reimplementing it in Rust. New multi-statement business logic is written as a
   reducer. Rust-side SQL is for work that is genuinely one statement, or that has no
   reducer and gains nothing from one.
3. **ARCH-026 still binds.** One route moves at a time behind a default-OFF flag, with a
   single writer per request, a parity oracle, unchanged one-transaction atomicity, R1–R4,
   no `SET ROLE`, and no success reported for a lost result. Only its rejection of
   "Rust calls the reducer" is withdrawn.

## Consequences

- The root invariant reads again: reducers own business logic; Go (and then Rust) translates
  protocols.
- Mark-read (#214) is rewritten to call `jmap_email_set_update`; the parity oracle stays the
  same and must stay green.
- The Rust implementation plan's "remove database-resident business reducers" target is
  superseded for version 1. Reducer removal, if ever, is a later per-command decision backed
  by measurement.

## Alternatives rejected

- **Keep reimplementing reducers in Rust and optimise** (prepared statements, set-based
  rewrites): possible, but every command would rebuild what the reducer already does in one
  round trip, and needs PgBouncer prepared-statement support to approach the same cost.
