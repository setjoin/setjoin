// verdict.ts — pure projection of VerifyAudit's response onto the THREE
// verdict outcomes the plan pins (verify N1): PASS / CHAIN BROKEN (TRUNCATED
// is a sub-case of broken, never a fourth state) / RECORD ALTERED. There is
// no ⚠ / "probably fine" state — a purge reconciliation is a neutral
// sub-line on an otherwise unqualified PASS, never a caveat.
import type { ChatAuditVerifyResult } from '$lib/admin/client';

export type ChatVerdictKind = 'pass' | 'broken' | 'altered';

export interface ChatVerdict {
	kind: ChatVerdictKind;
	/** Only meaningful when kind === 'broken'. */
	truncated: boolean;
	result: ChatAuditVerifyResult;
}

export function computeChatVerdict(result: ChatAuditVerifyResult): ChatVerdict {
	// Stage 1 (FIX 1) — a tail-truncated chain is CHAIN BROKEN, not a fourth
	// state. The server already omits anchors when this is true.
	if (result.truncationDetected) {
		return { kind: 'broken', truncated: true, result };
	}
	// Stage 2 — a mid-chain edit/delete.
	if (!result.chainValid) {
		return { kind: 'broken', truncated: false, result };
	}
	// Stage 3 — the chain itself is intact, but an anchor doesn't reconcile or
	// a revision rides no corresponding chained edit: RECORD ALTERED, a
	// failure in the same danger treatment as a broken chain (verify N1 — a
	// rewritten surviving message in a purged range must NOT read as the same
	// benign "reconciled" line destroyedElems is for).
	const altered = (result.anchors ?? []).some((a) => !a.valid || a.revisionsUnchained > 0);
	if (altered) {
		return { kind: 'altered', truncated: false, result };
	}
	return { kind: 'pass', truncated: false, result };
}
