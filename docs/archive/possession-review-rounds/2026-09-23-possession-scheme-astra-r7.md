Both r6 blockers are closed at specification level.

- Finish ordering (retired-docs:verification/2026-09-23-possession-scheme-v7.md:1161) now puts fences → durable revocation → budget → verification → counter recording/reset inside one transaction, consistent with §2.2/§2.3. Locked valid and invalid assertions return 429 without evaluation or ceremony consumption.
- Scenario B (retired-docs:verification/2026-09-23-possession-scheme-v7.md:1459) now inserts G_D directly, preserving G_C. This avoids [issuance’s user-wide deletion](/authserver/internal/handlers/mfa_reauth.go:146). The [schema](/mailserver/sql/dbschema/V271__mfa_reauth_step_ups.sql:48) permits the fixture; family-F deletion and family-F₂ grant usability remain independently observable.

The complete diff contains only the header and these two corrections. §2.2/§2.3 are byte-identical to v6; no regression found in the changed contracts.

Minor editorial discrepancy: `TestLockedFinishRefusesBothAssertionKinds` is specified inline, rather than added as a §4 matrix row. Its required behavior is explicit, so this does not block.

Read-only specification review; no tests run or implementation pass claimed.

ASTRA REVIEW: SHIP
