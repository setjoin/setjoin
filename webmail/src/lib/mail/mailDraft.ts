import { jmapCall } from '$lib/jmap/client';
import type { JmapMethodResponse } from '$lib/types/jmap';

export interface MailDraftSession {
	id: string;
	messageId: string;
	receivedAt: string;
	contentRevision: string;
	leaseEpoch: string;
	leaseHolderUserId?: string | null;
	leaseExpiresAt: string;
	finalSenderAddress?: string;
	replayed?: boolean;
}

export async function mailDraftLease(input: {
	accountId: string;
	session: MailDraftSession;
	action: 'renew' | 'release' | 'handoff' | 'takeover';
	targetUserId?: string;
	reason: string;
}): Promise<MailDraftSession> {
	const operationId = crypto.randomUUID();
	const data = await jmapCall([['MailDraft/lease', {
		accountId: input.accountId,
		operationId,
		id: input.session.id,
		action: input.action,
		expectedEpoch: input.session.leaseEpoch,
		...(input.targetUserId ? { targetUserId: input.targetUserId } : {}),
		reason: input.reason,
	}, operationId]]);
	return resultOf(data);
}

function resultOf(data: Awaited<ReturnType<typeof jmapCall>>): MailDraftSession {
	const response = data.methodResponses[0][1] as JmapMethodResponse;
	if (response && typeof response.type === 'string') {
		throw new Error(response.description || response.type);
	}
	return response as unknown as MailDraftSession;
}

export async function mailDraftOpen(input: {
	accountId: string;
	messageId: string;
	receivedAt: string;
	finalSenderAddress: string;
}): Promise<MailDraftSession> {
	const operationId = crypto.randomUUID();
	const data = await jmapCall([['MailDraft/open', { ...input, operationId }, operationId]]);
	return resultOf(data);
}

export async function mailDraftReplace(input: {
	accountId: string;
	session: MailDraftSession;
	draft: Record<string, unknown>;
}): Promise<MailDraftSession> {
	const operationId = crypto.randomUUID();
	const data = await jmapCall([['MailDraft/replace', {
		accountId: input.accountId,
		operationId,
		id: input.session.id,
		expectedEpoch: input.session.leaseEpoch,
		baseRevision: input.session.contentRevision,
		draft: input.draft,
	}, operationId]]);
	return resultOf(data);
}
