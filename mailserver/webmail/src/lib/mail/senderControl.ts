import { httpRequest, typedFetch } from '$lib/http';

export type SenderControlAction =
	| 'always_focus' | 'never_focus' | 'vip' | 'not_vip' | 'safe' | 'block'
	| 'never_block' | 'report_phishing' | 'report_spam' | 'undo';

export interface SenderControlState {
	sender: string;
	senderDigest: string;
	generation: string;
	alwaysFocus: boolean;
	neverFocus: boolean;
	vip: boolean;
	safe: boolean;
	blocked: boolean;
	operationId?: string;
	action?: SenderControlAction;
	replayed?: boolean;
}

export interface SenderControlTarget {
	mailboxId: string;
	messageId: string;
	receivedAt: string;
}

function query(target: SenderControlTarget): string {
	return new URLSearchParams({ mailboxId: target.mailboxId, messageId: target.messageId, receivedAt: target.receivedAt }).toString();
}

export async function readSenderControl(target: SenderControlTarget, signal?: AbortSignal): Promise<SenderControlState> {
	return typedFetch<SenderControlState>(`/api/settings/sender-control?${query(target)}`, { signal });
}

export async function applySenderControl(
	target: SenderControlTarget,
	action: SenderControlAction,
	expectedGeneration: string,
	targetOperationId?: string,
): Promise<SenderControlState> {
	const operationId = crypto.randomUUID();
	const response = await httpRequest('/api/settings/sender-control/actions', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Idempotency-Key': operationId,
			'If-Match': `"${expectedGeneration}"`,
		},
		body: JSON.stringify({ ...target, operationId, action, expectedGeneration, ...(targetOperationId ? { targetOperationId } : {}) }),
	});
	return (await response.json()) as SenderControlState;
}
