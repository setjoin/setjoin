# Maintainer registry-authoring workflow

This guide distinguishes the current A0 JSON registry from the V1A product
registry. The two must not be merged just because both contain Exchange names.

## Current A0 registry — implemented boundary

The current A0 registry is the embedded `v0` JSON used by `mailctl exchange-a0`
and the external registry file consumed by the fixed PowerShell collector. Each
row contains:

```text
id, title, outcome, commands[]
```

The Go implementation embeds its copy. The collector verifies the supplied file's
schema, requires that every command is in the compiled ten-command read-only
allowlist, and requires that every compiled command is represented. This prevents
the registry from becoming a dynamic execution language.

Changing an A0 row is an implementation change that must preserve the v0 digest,
strict validation, static command proof, deterministic report ordering, and
non-importable phase. This documentation task does not change that registry or
the collector.

## V1A product registry — implemented, default OFF

The product source lives under `config/exchange-replacement/` and is the
single source for capability IDs, administrator outcomes, Exchange source names,
Setjoin mappings, alternatives, exclusions, phase impact, evidence level,
workflow/test IDs, and documentation links. It is not the current A0 registry.

The authoring loop is:

1. **Choose a business capability.** Use a stable parent ID for an administrator
   outcome, not a cmdlet or parameter checklist. Record the source Exchange
   versions, object/property/cmdlet, discovery method, criticality, owner, release
   state, and explicit exclusions.
2. **Define the mapping.** Set `outcome_mapping` and describe the native,
   transformed, alternative, or none workflow. State target reducer/API/UI or
   runbook, migration/rollback behavior, security/privacy impact, and every phase
   impact. Never use a handwritten combined compatibility verdict.
3. **Bind the support cell.** Record the exact version/topology/runtime/catalog/
   registry/Setjoin tuple and its digest. An unknown build stays unsupported or
   unassessed until evidence admits it.
4. **Add fixtures and cases.** Cover success, zero, partial, permission denied,
   unsupported, hybrid-incomplete, CJK, large, adversarial, ordering, null/empty,
   unknown, and mutant omission cases as applicable. Every expected root/probe has
   a terminal result; zero is not complete without independent proof.
5. **Run the generator and focused verification.** The implemented front door is
   `scripts/verify-exchange-assessment.sh --doctor|quick|core|live`. `doctor`,
   `quick`, and `core` are intended to be hermetic; `live` requires a named
   support cell and fails closed when it is unavailable.
6. **Review every projection.** Inspect generated UI vocabulary, internal feature
   inventory, executive/admin reports, comparison docs, workbooks, JSON, tests,
   and inclusion manifests. Reject orphan IDs, untranslated labels, handwritten
   capability rows, and generated diffs without review.
7. **Attach evidence and invalidation.** Record artifact digests, support-cell
   digest, capture/expiry times, approvals, exact case IDs, and invalidation inputs.
   A support-cell or behavior-bearing release change makes the claim stale until
   the required evidence is restored.

## Add, retire, or split

These are V1A authoring rules, not A0 commands:

- **Add:** allocate a never-reused stable ID; define the outcome and all axes;
  add source mappings, exclusions, owner, cases, fixtures, docs link, and
  inclusion-manifest expectations before the row can project anywhere.
- **Retire:** preserve the ID and history; mark the reason, date, owner, and
  affected claims. Generated artifacts show the row as omitted only with that
  reason. Do not delete history or silently turn a retired row into supported.
- **Split:** create new child IDs with explicit predecessor links and separate
  acceptance/evidence units. Keep the old parent visible as superseded or
  reclassified, invalidate affected claims, and regenerate every projection.

One registry edit is intended to update UI labels, feature inventory, comparison
documents, reports, workbooks, JSON, and test selection. A maintainer must not
repair a generated diff by hand while leaving the source registry unchanged.

## Evidence boundary

T0 fixture evidence can support only the `experimental` label. T1 controlled
live evidence is needed for `provisional`; T2 representative live evidence is
needed for `supported`. The current repository copy does not provide customer,
controlled-live Exchange, representative-live Exchange, human acceptance, or
Windows execution-parity evidence. A maintainer must record those as missing or
unassessed rather than filling a registry field optimistically.
