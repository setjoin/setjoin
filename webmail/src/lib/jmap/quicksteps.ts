// Quick Steps JMAP client (Track A2) — thin wrappers over QuickStep/{get,set,apply}.
//
// The gateway resolves the mailbox id from the auth context (never the request),
// enforces the action allowlist (move_to/categorize/flag/mark_read/forward_to), and
// re-checks message ownership in the reducer. This module only shapes the call and
// surfaces the method-level error envelope as a thrown Error.

import { jmapCall, getAccountId } from './client';
import type { JmapMethodResponse, QuickStep, QuickStepAction } from '$lib/types/jmap';

/** Throw if the gateway returned a method-level error envelope (name "error"). */
function assertOk(resp: JmapMethodResponse): JmapMethodResponse {
	if (resp && typeof resp.type === 'string') {
		throw new Error(resp.description || resp.type);
	}
	return resp;
}

/** List the account's quick steps, ordered by position. */
export async function listQuickSteps(): Promise<QuickStep[]> {
	const accountId = await getAccountId();
	const data = await jmapCall([['QuickStep/get', { accountId }, '0']]);
	const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
	return ((resp.list as QuickStep[]) ?? []).map((qs) => ({
		...qs,
		actions: (qs.actions ?? []) as QuickStepAction[],
	}));
}

/**
 * Create (no id) or update (id given) a quick step. Returns the new/updated id.
 * The action allowlist is enforced server-side; an invalid action throws.
 */
export async function saveQuickStep(qs: {
	id?: string;
	name: string;
	icon: string;
	actions: QuickStepAction[];
}): Promise<string> {
	const accountId = await getAccountId();
	const args: Record<string, unknown> = {
		accountId,
		name: qs.name,
		icon: qs.icon,
		actions: qs.actions,
	};
	if (qs.id) args.id = qs.id;
	const data = await jmapCall([['QuickStep/set', args, '0']]);
	const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
	return resp.id ?? qs.id ?? '';
}

/** Delete a quick step by id. */
export async function deleteQuickStep(id: string): Promise<void> {
	const accountId = await getAccountId();
	const data = await jmapCall([['QuickStep/set', { accountId, id, destroy: true }, '0']]);
	assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

/** Run a quick step macro against one of the account's messages. */
export async function applyQuickStep(id: string, messageId: string): Promise<void> {
	const accountId = await getAccountId();
	const data = await jmapCall([['QuickStep/apply', { accountId, id, messageId }, '0']]);
	assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}
