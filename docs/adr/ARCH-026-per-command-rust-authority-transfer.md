# ADR: ARCH-026 — Per-command Rust authority via single-writer transfer

**Status:** Accepted; every transfer stays default-OFF until its own rollout decision.
Amended by [ARCH-028](ARCH-028-rust-replaces-go-reducers-stay.md): reducers stay where they save
round trips, and Rust calling a reducer is allowed.
**Date:** 2026-10-29
**Authority:** spec setjoin/setjoin#209 (RP07-S01), ticket #210; owner rewrite
decision 2026-10-11

## Context

The owner committed Setjoin to a Rust rewrite in which Rust commands, not
PL/pgSQL reducers, own business authority. Today the reducers in
`mailserver/sql/reducers/` are the live authority, and the root invariant
"Logic where the data is" says so without qualification. Moving every command at
once would leave no live baseline to compare against and no safe rollback. Letting
Rust and a reducer both write the same state would create split authority:
double state bumps, duplicate journal rows and pushes, and disagreement about
which result is true.

The numbers ARCH-024 and ARCH-025 are not used here: the reviewed Rust implementation
plan cites a retained ARCH-024 technical proposal still under review, and product spec
#191 cites an ARCH-025; neither file is in the repository yet. This ADR fixes only the
authority-transfer rule and adopts none of their details.

## Decision

1. **Authority moves one command at a time.** A reducer stays the business
   authority for its command until that command's qualified transfer. No family,
   domain or protocol transfers as a bundle.
2. **Parity oracle before transfer.** The current reducer behaviour is the
   contract. Each command gets a database-backed parity test that passes against
   the reducer first and then, unchanged, against the Rust command. A transfer is
   qualified only when that oracle passes and the command's applicable reviews are
   complete.
3. **Single writer at all times.** Each transferred command has one flag that
   selects the Rust command **or** the reducer as writer, never both. The flag
   defaults OFF (reducer writes). There is no dual-write, shadow-write or
   write-then-compare mode against live data.
4. **Atomicity is unchanged.** Whichever implementation writes, the data change,
   state bump, audit/journal rows and `pg_notify` commit in one transaction.
   Rust does not split them across transactions or move them into post-commit
   gateway code.
5. **Database rules still bind Rust.** R1–R4
   ([DATABASE_SECURITY.md](../standards/DATABASE_SECURITY.md)) apply to Rust
   queries. Privileges come from credentials, never `SET ROLE` on a shared pool;
   statements must work behind the PgBouncer transaction pool (`DB_DSN`).
6. **A lost result never reports success.** If the commit outcome is unknown,
   the command returns its operation ID for lookup instead of claiming success.
7. **Turning a flag ON is a separate rollout decision.** Passing the oracle
   qualifies a transfer; it does not enable it.

## Consequences

- The root invariant reads "reducers own authority until a command's qualified
  transfer"; for any command whose flag is OFF the reducer is authoritative.
- Each transfer ships a parity test, a default-OFF flag and a rollback path
  (flag OFF returns writing to the reducer). The reducer stays in place until the
  transfer is accepted and a later change removes it.
- Reviewers can reject any change that writes one command's state from both
  implementations, or that weakens the one-transaction requirement in either.
- The first transfer is `$seen` (mark-read) from `jmap_email_set_update`
  (RP07-S01); later commands follow the same rule without a new ADR.

## Alternatives rejected

- **Big-bang cutover:** no live baseline, no per-command rollback.
- **Dual-write or shadow-write:** violates single-writer; risks double bumps,
  duplicate pushes and diverging state.
- **Rust in front of reducers (Rust calls the reducer):** *(withdrawn by ARCH-028)* keeps the reducer as
  the real authority and defers, rather than performs, the transfer.
