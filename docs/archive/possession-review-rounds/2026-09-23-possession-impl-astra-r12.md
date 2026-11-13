Residual closed. The [helper persists the truncated watermark](/authserver/internal/handlers/possession_matrix_test.go:465), so `NewNumericDate(notBefore)` preserves exact equality. Changing `<=` to `<` would admit the boundary claimant with its valid grant, failing the [403 assertion](/authserver/internal/handlers/possession_matrix_test.go:580). The strictly-after control requires 200.

No new blocking findings in this delta. Equality is established by construction; there is no separate equality assertion. Read-only source review; I did not rerun tests or mutation injection. The named round-11 receipt was absent.

ASTRA REVIEW: SHIP — normalized fixture discriminates `<=` from `<`; no new blockers found.
