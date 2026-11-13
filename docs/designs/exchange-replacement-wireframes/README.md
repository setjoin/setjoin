# Exchange Replacement D0 static wireframes

This directory is a dependency-free, version-controlled wireframe prototype for
the Exchange Replacement admin area. Open [`index.html`](./index.html) directly
in a browser; no build system, server, package install, production data, or
network request is required.

## What is covered

The prototype keeps one existing Mail-console shell with a persistent project
selector and URL-scoped immutable run selector. The six primary views are:

| Wireframe surface | Plan/design contract coverage |
| --- | --- |
| Overview | UI Contract: first-screen decision priorities; V1A lifecycle phase; independent assessment, mapping, and claim axes; denominator, evidence freshness, blockers, and next safe action. |
| Assessments | UI Contract: immutable runs, support cell, collector/catalog digests, terminal probe groups, receipts, resumable partial run, and diagnostic recovery. |
| Outcomes | UI Contract: outcome-first registry inventory; native, transformed, alternative, unsupported, unassessed, and excluded states; dense Exchange-versus-Setjoin comparison. |
| Mappings | UI Contract: masked source anchors, mapped/review/unresolved/collision queues, phase impact, accountable owner, and no bulk accept-all. |
| Documents | UI Contract: registry-backed executive/admin/comparison/workbook/JSON artifacts, stale digest handling, inclusion manifest, and deterministic export. |
| Settings | D0 handoff coverage for project identity, data handling, all seven granular permissions, and artifact/run/project disposal previews. |

The plan's separate **Evidence** information-architecture row is represented as
the persistent evidence context panel shared by all six requested views. It keeps
the primary navigation at the six surfaces requested for this bounded artifact
while still showing T0/T1/T2, freshness/invalidation, reader-versus-auditor
visibility, and recovery behavior.

## Contract details made visible

- `V1A` is headed **“Assessment only — replacement readiness not established.”**
- A0 static HTML/PDF/JSON reports and receipts are labeled reference-only and
  explicitly **never importable as product runs**.
- There is no aggregate Exchange compatibility score. Assessment status, mapping
  coverage, and claim state remain separate; unknown is not zero.
- The state shelf demonstrates loading, empty, error, ready, partial, stale, and
  permission-denied recovery copy. State changes are announced through one
  bounded `aria-live="polite"` region.
- The Settings permission matrix names:
  `migration.assessment.read`, `.run`, `.decide`, `.attest`, `.audit`, `.publish`,
  and `.delete`, including hidden/ungranted actions and fresh-authority notes.
- Long blockers, partial/latest run comparison, dense outcome comparison,
  multi-actor handoff, and artifact/run/project deletion previews are visible.
- Sensitive identifiers are masked by default, and actions are intentionally
  static examples; the prototype claims no operator or administrator validation.

## Responsive and accessibility intent

The CSS follows the approved visual contract using standalone copies of the
existing Setjoin color, type, spacing, radius, and focus-ring tokens. The shell
uses a 232px desktop sidebar, an in-flow evidence context panel below 1200px,
and a focusable drawer plus labeled view selector below 768px. Tables retain
semantic captions/headers on desktop and become one disclosure record per row on
mobile. Outcome records retain a two-column Exchange-versus-Setjoin mini-table.

The prototype includes semantic landmarks, headings, labels, focus-visible
styles, keyboard-reachable controls, touch-sized controls, bilingual `en-US` /
`zh-CN` switching, URL hash view selection, and reduced-motion handling. The
approved 200% zoom/browser matrix and representative Exchange-administrator
sign-off remain D0 evidence gates; they have not been run or claimed here.

## Files

- `index.html` — static shell and all six view surfaces.
- `styles.css` — standalone Setjoin-token-aligned responsive styles.
- `wireframe.js` — dependency-free language, view, state, mobile drawer, and
  URL-hash behavior.
- `verify.sh` — deterministic structural checks limited to this directory.

## Verification

From this directory, run:

```sh
bash verify.sh
```

The script checks required files and contract markers without starting a server,
reading credentials, or modifying files. `git diff --check` is an additional
repository-level whitespace check for this change.
