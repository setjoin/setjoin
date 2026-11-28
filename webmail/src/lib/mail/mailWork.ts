import { jmapCall } from '$lib/jmap/client';
import type { JmapMethodResponse } from '$lib/types/jmap';

export type MailWorkStatus = 'unassigned' | 'owned' | 'waiting' | 'done';
export type MailWorkFilter = 'all' | 'mine' | 'due_soon' | 'breached' | MailWorkStatus;
export type MailWorkAction = 'claim' | 'assign' | 'status' | 'due' | 'handoff';
export type MailWorkIntegrationAction = 'task' | 'chat' | 'drive';

export interface MailWorkItem {
	id: string;
	threadId: string;
	status: MailWorkStatus;
	assigneeUserId: string | null;
	dueAt: string | null;
	generation: string;
	lastActivityAt?: string;
	slaBreachedAt?: string | null;
}

export interface MailWorkProjection {
	accountId: string;
	state: string;
	list: MailWorkItem[];
}

export function mailWorkMatchesFilter(item: MailWorkItem | undefined, filter: MailWorkFilter, userId?: string | null, now = new Date()): boolean {
	if (filter === 'all') return true;
	if (filter === 'unassigned') return !item || item.status === 'unassigned';
	if (filter === 'mine') return !!userId && item?.assigneeUserId === userId && item.status !== 'done';
	if (filter === 'breached') return !!item?.slaBreachedAt && item.status !== 'done';
	if (filter === 'due_soon') {
		if (!item?.dueAt || item.status === 'done' || item.slaBreachedAt) return false;
		const due = Date.parse(item.dueAt);
		return Number.isFinite(due) && due > now.getTime() && due <= now.getTime() + 24 * 60 * 60 * 1000;
	}
	return item?.status === filter;
}

export type MailWorkNotificationDelivery = 'immediate' | 'digest' | 'off';
export interface MailWorkNotificationPreference {
	category: string;
	delivery: MailWorkNotificationDelivery;
	timezone: string;
	digestHour: number;
	generation: string;
}

export interface MailWorkMetrics {
	accountId: string;
	available: boolean;
	reason?: 'cohort_floor';
	minimumActors?: number;
	minimumConversations?: number;
	policyVersion?: number;
	list?: MailWorkMetricDay[];
}

export interface MailWorkMetricDay {
	metric_day: string;
	policy_version: number;
	conversation_count: number;
	first_response_count: number;
	first_response_seconds: number | string;
	completed_count: number;
	breached_count: number;
	actor_cohort_count: number;
	rebuilt_at: string;
}

export interface MailCommentMention {
	userId: string;
	capability: 'comment' | 'view_only';
}

export interface MailWorkCollaborator {
	id: string;
	displayName: string;
	email: string;
	capability: 'comment' | 'view_only';
}

export interface MailWorkSLAPolicy {
	version: number;
	timezone: string;
	weekdayMask: number;
	workdayStart: string;
	workdayEnd: string;
	holidays: string[];
	slaMinutes: number;
	generation?: string;
	source: 'organization_default' | 'mailbox';
}

export interface MailWorkPolicyProjection {
	accountId: string;
	canManage: boolean;
	policy: MailWorkSLAPolicy;
	updatedAt?: string | null;
	updatedBy?: string | null;
}

export interface MailActivityItem {
	kind: 'comment' | 'event';
	id: string;
	body?: string | null;
	authorDisplay?: string;
	authorUserId?: string | null;
	actorDisplay?: string;
	eventType?: string;
	edited?: boolean;
	tombstoned?: boolean;
	mentions?: MailCommentMention[];
	createdAt?: string;
	occurredAt?: string;
}

function assertOk(resp: JmapMethodResponse): JmapMethodResponse {
	if (resp && typeof resp.type === 'string') throw new Error(resp.description || resp.type);
	return resp;
}

export async function mailWorkGet(accountId: string, threadId: string | string[]): Promise<MailWorkProjection> {
	const ids = Array.isArray(threadId) ? threadId : [threadId];
	const data = await jmapCall([['MailWork/get', { accountId, ids }, 'mail-work-get']]);
	return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as unknown as MailWorkProjection;
}

export async function mailWorkCollaboratorsGet(accountId: string, query: string, limit = 20): Promise<MailWorkCollaborator[]> {
	const data = await jmapCall([['MailWorkCollaborators/get', { accountId, query, limit }, 'mail-work-collaborators-get']]);
	const response = assertOk(data.methodResponses[0][1] as JmapMethodResponse) as JmapMethodResponse & { list?: MailWorkCollaborator[] };
	return response.list ?? [];
}

export async function mailWorkPolicyGet(accountId: string): Promise<MailWorkPolicyProjection> {
	const data = await jmapCall([['MailWorkPolicy/get', { accountId }, 'mail-work-policy-get']]);
	return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as unknown as MailWorkPolicyProjection;
}

export async function mailWorkPolicySet(input: {
	accountId: string;
	expectedGeneration: string;
	timezone: string;
	weekdayMask: number;
	workdayStart: string;
	workdayEnd: string;
	holidays: string[];
	slaMinutes: number;
}): Promise<MailWorkPolicyProjection & { operationId: string; replayed: boolean }> {
	const operationId = crypto.randomUUID();
	const data = await jmapCall([['MailWorkPolicy/set', { ...input, operationId }, operationId]]);
	return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as unknown as MailWorkPolicyProjection & {
		operationId: string;
		replayed: boolean;
	};
}

export async function mailWorkSet(input: {
	accountId: string;
	threadId: string;
	action: MailWorkAction;
	expectedGeneration: string;
	assigneeUserId?: string;
	status?: MailWorkStatus;
	dueAt?: string | null;
	reason: string;
}): Promise<MailWorkItem & { state: string; operationId: string; replayed: boolean }> {
	const operationId = crypto.randomUUID();
	const payload = { ...input, operationId };
	const data = await jmapCall([['MailWork/set', payload, operationId]]);
	return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as unknown as MailWorkItem & {
		state: string;
		operationId: string;
		replayed: boolean;
	};
}

export async function mailWorkAction(input: {
	accountId: string;
	threadId: string;
	expectedGeneration: string;
	actionKind: MailWorkIntegrationAction;
	targetId?: string;
}): Promise<{ eventId: string; outboxId: string; generation: string; replayed: boolean }> {
	const operationId = crypto.randomUUID();
	const data = await jmapCall([['MailWork/action', { ...input, operationId }, operationId]]);
	return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as unknown as {
		eventId: string;
		outboxId: string;
		generation: string;
		replayed: boolean;
	};
}

export async function mailCommentGet(accountId: string, threadId: string): Promise<MailActivityItem[]> {
	const data = await jmapCall([['MailComment/get', { accountId, threadId, limit: 100 }, 'mail-comment-get']]);
	const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse) as JmapMethodResponse & { list?: MailActivityItem[] };
	return resp.list ?? [];
}

export async function mailCommentSet(input: {
	accountId: string;
	threadId: string;
	expectedGeneration: string;
	body: string;
	mentionUserIds?: string[];
	replacesCommentId?: string;
	handoffUserId?: string;
}): Promise<void> {
	const operationId = crypto.randomUUID();
	const data = await jmapCall([['MailComment/set', { ...input, operationId }, operationId]]);
	assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function mailWorkNotificationPreferencesGet(accountId: string): Promise<MailWorkNotificationPreference[]> {
	const data = await jmapCall([['MailWorkNotificationPreferences/get', { accountId }, 'mail-work-prefs-get']]);
	const response = assertOk(data.methodResponses[0][1] as JmapMethodResponse) as JmapMethodResponse & {
		list?: MailWorkNotificationPreference[];
	};
	return response.list ?? [];
}

export async function mailWorkNotificationPreferenceSet(input: {
	accountId: string;
	category: string;
	delivery: MailWorkNotificationDelivery;
	timezone: string;
	digestHour: number;
	expectedGeneration: string;
}): Promise<MailWorkNotificationPreference> {
	const operationId = crypto.randomUUID();
	const data = await jmapCall([['MailWorkNotificationPreferences/set', {
		...input,
		operationId,
	}, operationId]]);
	return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as unknown as MailWorkNotificationPreference;
}

export async function mailWorkMetricsGet(accountId: string, from: string, to: string): Promise<MailWorkMetrics> {
	const data = await jmapCall([['MailWorkMetrics/get', { accountId, from, to, policyVersion: 1 }, 'mail-work-metrics-get']]);
	return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as unknown as MailWorkMetrics;
}
