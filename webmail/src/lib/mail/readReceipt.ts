/**
 * Read-receipt (MDN) client-side decision helper (Track A privacy).
 *
 * The RECIPIENT controls whether a read receipt is ever sent. The reducer
 * send_read_receipt() is the hard server-side gate; this helper decides what the
 * webmail does when a message that requested a receipt is opened, given the user's
 * effective policy:
 *   never  → never send, never prompt.
 *   always → auto-send (consent implied).
 *   ask    → prompt the user (no auto-send); the user's choice is POSTed as consent.
 * A non-receipt message (requested=false) is always a no-op.
 */
export type ReceiptPolicy = 'ask' | 'always' | 'never';

export interface ReceiptAction {
	/** Whether to POST the read receipt immediately (no user interaction). */
	send: boolean;
	/** Whether to show the consent prompt to the user. */
	prompt: boolean;
	/** Consent value to send when auto-sending (only present for 'always'). */
	consent?: boolean;
}

export function resolveReceiptAction(policy: ReceiptPolicy, requested: boolean): ReceiptAction {
	if (!requested) return { send: false, prompt: false };
	if (policy === 'never') return { send: false, prompt: false };
	if (policy === 'always') return { send: true, prompt: false, consent: true };
	return { send: false, prompt: true }; // ask
}
