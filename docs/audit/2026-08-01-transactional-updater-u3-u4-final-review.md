# Transactional updater U3/U4 final independent review — 2026-08-01

Scope: correction-only, read-only Claude Code Opus 5 review after Codex's U3/U4
implementation, runtime rehearsal, browser verification, and test pass.

## Review sequence

The first broad review attempt returned an empty malformed CLI response and was
treated as non-blocking. A narrower review scored the implementation 7/10 and
identified four valid low/medium gaps plus one previous-release integrity concern.
Codex accepted and corrected the valid findings:

- removed unused exported naive SQL-classification helpers;
- required a rollback adapter whenever a claim-enabled catalog crosses maintenance;
- required canonical non-nil recovery UUIDs and lowercase digests before provider contact;
- made claim replay return and compare complete release, manifest, recovery-set,
  and lease authority without caller-owned overwrites.

Unit, integration, and 81/81 transactional-upgrade pgTAP assertions cover the
accepted corrections. Codex rejected the previous-tree concern because
`ActivatePrevious` calls `validateManagedReleaseDir` before switching; that
validates fixed artifacts, canonical manifest/digest or adoption evidence, and
the installed full-tree evidence.

## Final verdict

The correction-only final review independently confirmed all four accepted
corrections and confirmed that the previous-tree rejection was correct. Its
verdict was:

> Residual blockers: none. Score: 10/10. All five corrections are present,
> correct, and regression-tested. The finding-5 rejection holds.

Claude was read-only and did not modify, stage, commit, push, deploy, or receive
credentials or production artifacts. Codex remains the implementation and final
decision authority.
