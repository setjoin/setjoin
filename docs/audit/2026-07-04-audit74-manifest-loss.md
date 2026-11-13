# The 2026-06-28 exhaustive audit's 74-Important manifest is unrecoverable

Queue B item 7 (`retired-docs:superpowers/plans/archive/2026-07-04-queue-b-combined.md` §7),
2026-07-04.

## What happened

The 2026-06-28 exhaustive audit (internal id `wlfnhc08z`) verified 84 security
findings — 10 Critical, 74 Important — across 160 modules. The full report
was written to `.superpowers/sdd/exhaustive-audit-report.json`. That path is
git-ignored scratch (`.superpowers/sdd/.gitignore` is a bare `*`), was never
committed anywhere else, and no longer exists on disk. Grepping the whole
repo (working tree + `git log -p` across all refs) for `wlfnhc08z` or
`exhaustive-audit` turns up nothing but the TODOS.md summary written the same
day.

What survives, because it was written directly into `TODOS.md` (not the
JSON):

- **The 10 Criticals**, individually itemized with file:line and a one-line
  fix description (`TODOS.md`, "EXHAUSTIVE AUDIT" section). Machine-guarded
  going forward by `scripts/check-audit74-criticals.sh` (this queue item).
- **One prose sentence** naming ~10 example categories from the 74 Important
  ("admin folder domain-scope bypass, admin_alerts config-allowlist bypass,
  auth SM2 verify unwired, caldav iMIP header injection, ldap STARTTLS not
  enforced + unscoped queries, linkprotect XFF spoof + fail-safe, ratelimit
  data race, cron 60x fire, kql placeholder collision, metrics double-count,
  etc.") followed by "Important-fix wave after the Criticals." No per-finding
  file:line list for the roughly 64 Important findings this sentence doesn't
  name.
- Two adjacent lists produced by the same audit lineage that DO have
  per-finding file:line specificity: the 33 "W-REVERIFY minors" and the 25
  "W-IMPORTANT-verify" (fix-is-correct-test-is-missing) items. These are not
  the 74-Important list itself, but they're the closest surviving material
  with enough detail to act on — see
  `docs/audit/2026-07-04-audit74-important-backlog.md`.

## Decision: accept the loss, don't reconstruct

Re-running a fresh exhaustive audit to regenerate a list that already claimed
(via the `production-hardening` branch, merged to `main` at `5b5ce313`) to be
fully fixed would be redoing Critical-fix-wave-scale work for uncertain
marginal value. The 10 Criticals — the highest-severity, most surviving-detail
tier — are separately guarded (see above). The ~64 unenumerable Important
findings are not reconstructed here.

## Process fix (so this can't recur)

Any future exhaustive-audit report **must be committed to a durable path**
(`docs/audit/`, following this file's own convention) — never to
`.superpowers/sdd/` or any other git-ignored scratch directory. If an audit
workflow only writes to scratch by default, copy the final report into
`docs/audit/YYYY-MM-DD-<name>-audit-report.json` (or `.md`) as a required last
step before considering the audit done.
