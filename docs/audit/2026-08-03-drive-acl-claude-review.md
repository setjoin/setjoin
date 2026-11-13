# Drive ACL independent Claude review — 2026-08-03

**Reviewer:** Claude Code Opus 5, `xhigh`

**Mode:** repository-aware, prompt-enforced read-only; no repository mutation,
formatting, staging, commit, push, or deployment authorized

**Material:** Drive ACL design spec, execution plan, ARCH-020, Drive glossary,
controlling Drive/RLS/native/testing contracts, and current implementation

**Initial verdict:** 4/10; not ready for implementation until five blockers and
major follow-ups were resolved in the plan

## Disposition

All findings were accepted. None challenged a confirmed user decision.

| ID | Severity | Finding | Accepted correction |
|---|---|---|---|
| B1 | Critical | No normalized user-keyed group authorization substrate | Add A0.5 directory groups/members/generation and transition invalidation before ACL schema |
| B2 | Critical | Subtree move omitted from access-generation changes | Move updates closure/content/access/audit/notify atomically |
| B3 | High | Unconsumed export grant survives access revocation | Recheck exact effective download access at consume and make approval grant unique |
| B4 | High | Narrowed RLS truncates invoker recursive walks | Move cycle/subtree/ancestor facts into closure-backed ARCH-018 helpers |
| B5 | High | Preview/download split trusts a client header and lacks renditions | Preview returns server-generated derivative only; unsupported types require download |
| M1 | Major | Hidden-only change page can starve cursor | Advance over last scanned sequence, not last visible row |
| M2 | Major | Bidirectional mirror cannot apply writes under traverse-only paths | Quarantine local operations and never upload/drop silently |
| M3 | Major | Direct Guest grants unspecified | Allow on ordinary/personal spaces under all Guest caps; reject on bound spaces |
| M4 | Major | DES-009 linked-node immutability absent from capability result | Force modify/rename/move/delete false for linked nodes |
| M5 | Major | Approval narrowing and export retry idempotency underspecified | Validate applied payload as a narrowing subset and enforce one grant per approval |
| R1 | Low | Stale folder-admin migration | Migrate live members only; drop stale rows with audit |
| R2 | Low | Full resync correction lacked exact algorithm | Stable complete set diff, revoke absent, quarantine pending edits, atomic cursor commit |
| R3 | Low | New helper posture not explicit | Pin the full ARCH-018 ownership/search-path/EXECUTE recipe |
| R4 | Low | Rollback no-widening claim not falsifiable | Add inheritance-break and moved-subtree toggle-off tests |
| R5 | Low | Traverse-only UI state missing | Add `traverseOnly`; locked/dimmed breadcrumb-only presentation |
| R6 | Low | Admin/eDiscovery carve-outs vague | Name the narrow BYPASSRLS allowlist and permission/audit checks |
| R7 | Low | Vault key/chunk cleanup vague | Remove manifests/keys and reference-aware evict chunks on revoke |
| R8 | Low | Personal-space node sharing unspecified | Permit selective sharing; preserve admin metadata-only boundary |

## Codex synthesis

The review found implementation-specific gaps, especially the absent group authority
substrate, additive-only sync reset, current export consume behavior, RLS-sensitive
recursive walks, and client-asserted render header. Every correction is in scope for
the requested complete Drive access-governance project and was folded into the
specification and plan before `/autoplan` scoring.
