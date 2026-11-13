# Program directory

**Resumed 2026-10-29** (paused earlier that day; checkpoint index `HANDOVER.md` on
branch `handover/dots-to-local-20261029`). Active work: the Rust rewrite, starting with
the RP07-S01 mark-read tracer bullet. The P0 quality-tool catalog probe HOLD is
dropped (owner decision 2026-10-29); its archive stays on
`handover/p0-catalog-archive-20261029`.

**Rust rewrite committed 2026-10-11; target revised 2026-10-29 (ARCH-028):** Rust replaces
Go route by route behind the Rust front door (ARCH-027); PL/pgSQL reducers stay wherever they
save round trips. Plan: `retired-docs:superpowers/plans/2026-10-22-setjoin-rust-implementation/` on
branch `plan/setjoin-rust-implementation-20261022` (its "remove reducers in version 1" target is
superseded). Avoid new investment in Go code; reducers remain the business-logic home.

Moved from the root rail on 2026-09-11 without changing any plan score, authority or
execution gate. Paths below are repository-relative. Consult the owning plan and current
queue for task-specific changes; this directory is not implementation permission.

## Active programs

- **Composable Workplace:** accepted product direction, documentation-only. Protected
  system apps, qualified provider seams and owned lifecycle; no universal hot reload
  or implementation approval. Cross-project sequencing and changed-scope review:
  `retired-docs:superpowers/plans/2026-09-06-composable-platform-refactor.md`; existing-plan
  reconciliation and claim gates are linked there. Domain security/evidence owners
  and admitted defaults remain unchanged.

- **Whole-Codebase Security Coverage:** C0 freezes 5,824 first-party paths across
  S01-S30. T7-ROUTE and T7-DX pass local zero-launch acceptance; final fresh Sol xhigh
  review scored T7-DX 10/10 with no P0/P1/P2. C0.5 and later gates require separate approval. Authority:
  `retired-docs:superpowers/plans/2026-08-30-whole-codebase-security-coverage.md`.
  The 2026-09-09 GLM-5.3-Flash deep-run audit and bounded Astra calibration are evidence-only:
  `retired-docs:verification/2026-09-09-zcode-deep-glm-astra-calibration.md`.

- **Security Boundary Remediation + Deep-Scan ER program:** the predecessor's
  15 findings remain closed; ER4 reconciled 26 overlaps (21 derived / 5 distinct,
  none reopened). ER1–ER5 and ER8 are complete; all 143 sealed occurrences are
  `fixed`, with the historical Astra + second-voice receipts retained.
  ER6 register/DOX reconciliation
  is complete for its documented scope. The readiness fixes in PR #120 and
  nightly-16 fixes in PR #121 landed. The integrated ER6 final gates RAN on
  2026-09-29 against pinned merge `7a5b5746` and are recorded with per-lane dated
  evidence (2026-09-29-er6-integrated-final-gates.md,
  11 lanes all final); the R3 rerun arm closed separately
  (2026-09-29-r3-rerun-arm-completion.md).
  Three findings are recorded and routed, none of them blocking this program: the
  webmail `@tiptap` audit advisories (dependency owner), the `offline-core` clippy
  `while_let_loop` lint (clients owner), and the boundary-manifest v1/v2 checker
  layout decision — RESOLVED 2026-10-01: owner went v1-flat, the runner publishes
  the checker's layout, all 8 lanes republished passed on `736f1605`, and the
  aggregate manifest is checker-reconciled (`b817f1b4c`), closing ER6 lane 9.
  One lane is a recorded scope-out (protocol, needs the Docker IMAP stack). Remaining:
  ER7 final dual-voice review CLOSED 2026-10-01 — both voices SHIP at
  `44e8baacc` (receipt;
  astra xhigh first voice after two fix rounds, claude-opus-5-5 second voice per
  the owner's routing after a 7-step fix plan and three review rounds). The
  program's gates are complete; OPEN residuals keep their owners.
  `releaseReady: 0` remains binding — gate completion admits no flag, rollout, or
  scanner invocation.
  Authorities: `retired-docs:superpowers/plans/2026-08-26-security-boundary-remediation.md`
  and `retired-docs:superpowers/plans/2026-08-28-deep-security-scan-remediation.md`.
  SEC-DP1 transition-proof deepening is CLOSED 2026-09-29: the review-close
  receipt (2026-09-29-sec-dp1-close-receipt.md)
  records the step-5 empty defect classification over all 143 rows, the
  SEC-DP1-A–E binding, dated gates at `c7c3f0a2c` (wrapper 65/65, Go green),
  Astra SHIP after three binding rounds and the Opus 5.5 second voice with its
  commit-binding finding resolved. It is not a new validated occurrence or
  changed closure count.

- **Meet Document Presentation and Semantic Replay:** M0–M5, M6 slice 1
  (word/spreadsheet modes) and slice 2 (continuity proofs and NULL-actor fence
  correction), Drive History emitter V269 and lobby mint fence V270/BZ329 landed
  through PRs #120/#121. Flags remain OFF. The
  [renderer qualification](../verification/2026-09-20-meet-renderer-qualification.md)
  completed on darwin/arm64 and selected pdfium chromium/8057 under the
  LibreOffice single-suite constraint; the production pin still needs linux-ci-host
  re-qualification. Remaining: pinned Egress audio evidence (MP-AUDIO-001),
  M6's remaining compatibility breadth, M7 operations/rollout and the existing
  external gates. Authority:
  `retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-recording.md`.
  MEET-DP1 is a P1 **planned M3 lifetime follow-up** for cancellation and late
  responses; source inspection is not executed evidence and admits no flag change.

- **Office Foundation and Drive History:** H0 plus the default-OFF provider-neutral
  Office authority, WOPI proof/fence/save path, unified admin/CLI surfaces and
  controlled Electron local-open are implemented. The closed managed-CODE vertical
  additionally has reducer-authoritative install/recovery, lease-safe execution,
  fail-closed Docker ownership, unified Apps/Office UI and read-only deployment-source
  projections, with a real disposable-Docker browser lane. V227 admits the
  pre-release production defaults and the installer starts the closed managed
  runner; provider routing still requires qualification and explicit activation.
  Live customer, legal, load/HA, domestic-platform and independent-operator evidence
  remain release-claim gates. Authorities:
  `retired-docs:superpowers/plans/2026-08-24-office-foundation-history-explorer.md` and
  `retired-docs:superpowers/plans/2026-08-24-office-architecture-deepening-and-board-closure.md`.

- **Exchange Replacement Contract:** the default-OFF V1A registry/compiler,
  31-outcome collector, strict bundle/import path, reducer-authoritative lifecycle,
  seven permissions, unified admin UI, encrypted/signed artifacts and honest
  deletion worker are implemented alongside the internal A0/v0 lane. The A0/D0
  provenance item is CLOSED (owner decision 2026-09-19, path (b): deviation
  acknowledged + prospective decision —
  `retired-docs:verification/2026-09-19-owner-consolidated-decisions.md`); the substantive
  A0 exit evidence and D0 two-administrator reviews remain REQUIRED before any
  external/customer EX evidence step; internal work continues. Release claims
  remain blocked on real customer/controlled-Exchange, Windows policy, retained
  binary, benchmark and independent handling evidence; none is fabricated. Authority:
  `retired-docs:superpowers/plans/2026-08-23-exchange-replacement-contract.md`.

- **Architecture Deepening Round 3:** R0–R9 implementation is complete with all
  production behavior OFF. Final aggregate/correction-source compatibility still
  needs reconciliation before dossier closure; retained N-1,
  physical-device, pinned live-media, and full Chat/Meet interaction evidence remain
  explicit release gates; the independent DX boomerang passes. Authority:
  `retired-docs:superpowers/plans/2026-08-13-architecture-deepening-round-3.md`.

- **Connectivity-Aware Sync and Resource QoS:** E0–E5, E4-I production boot,
  E6 profile/harness/driver, paired-client launcher, gateway fixture and native
  bridge are implemented. The E7 contract and dossier exist; all six E7 cases
  are bound in the current checkout, still `planned` (#124 merged; Commit A
  authorized 2026-09-29 —
  authorization record,
  sustained run still gated on an isolated host + owner decision). All
  production flags remain OFF. E6 generation
  `e6h-20260922t024022z-9915a0663542` completed **20/20 pairs, FAIL** at
  15:22 CST on 2026-09-22: accounting passes; sample-floor, paired-regression
  and crossprocess gates fail. All five Critical-class claims are unavailable.
  Run-owner receipt binding/diagnosis remains; E7 stays blocked.
  Harness status and result-consumption rules
  own the live-run handoff. Only an accepted passing E6 receipt can satisfy the
  E6 prerequisite for separately admitted E7 pilot work; retained pre-V209
  compatibility evidence remains open. Authority:
  `retired-docs:superpowers/plans/2026-08-11-connectivity-aware-sync-resource-qos.md`.
  CQ-DP1 atomic page/checkpoint composition and CQ-DP2 inert instrument import are
  P1 **planned follow-ups** under E4-I/E6. No source changes while measurement runs;
  later changes require explicit evidence-reuse comparison and affected qualification.
- **Transactional Upgrade and Mail Continuity:** U-1–U7, portable Ubuntu rewind,
  and simulator restart/resume pass with execution OFF. U8 remains open only for
  physical iOS/Android and independent-operator timing evidence. Authority:
  `retired-docs:superpowers/plans/2026-08-01-transactional-upgrade-continuity.md`.
- **Managed Dependency Coordination:** plan-quality10/10; execution-held plan extends the signed updater
  with receipted local PostgreSQL/PgBouncer, native SeaweedFS and optional Collabora
  compatibility groups under one Manifest v2. No implementation is authorized;
  remote PostgreSQL and major/HA transitions remain deferred. Authority:
  `retired-docs:superpowers/plans/2026-09-01-managed-dependency-coordination.md`.
- **Webmail loading performance:** implementation and five-sample real-gateway
  surrogate pass. Release closure still requires a supported-host 20-sample run
  and update rehearsal from the retained prior signed artifact. Authority:
  `retired-docs:superpowers/plans/2026-08-09-webmail-loading-performance.md`.

- **Debt Consolidation:** D1–D6 delivery is recorded in September 18–19 commits
  and nightly review receipts; an itemized source/acceptance/review reconciliation
  is still needed before archival. Reuse completed fixes, retain the separately
  named migration follow-ups, and do not infer a new implementation gap from
  stale RUNBOOK prose. Authority:
  `retired-docs:superpowers/plans/2026-09-18-debt-consolidation.md`;
  receipt map.

The exact queue is the GitHub issue tracker; the plan index is
`retired-docs:superpowers/plans/README.md`. Completed, superseded, and cold backlog plans
live under `retired-docs:superpowers/plans/archive/`; their as-built portfolio and evidence
index is `docs/AGENTS.md`. Production flags remain OFF unless a separate rollout
decision explicitly enables them.
