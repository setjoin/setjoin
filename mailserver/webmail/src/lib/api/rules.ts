// End-user mail-rules client — the security-scoped /api/settings/rules routes.
// Uses the schema-first openapi-fetch edgeClient routed over httpRequest (DPoP
// proof signing + 401 admission recovery + timeout). The gateway forces the
// caller's own primary mailbox + non-transport, so we never send mailboxId or
// isTransportRule on writes.

import { createEdgeClient, toEdgeProblemError, type components } from '$lib/edge/client';
import { problemDetail } from '$lib/errors';

/** A simple rule-engine condition (mirrors eval_condition in rule_engine.sql). */
export type RuleCondition = components['schemas']['Rules.RuleCondition'];

/** A rule-engine action (mirrors apply_action in rule_engine.sql). */
export type RuleAction = components['schemas']['Rules.RuleAction'];

export type RunOn = components['schemas']['Rules.RunOn'];

type WireUserRule = components['schemas']['Rules.UserRule'];

export interface UserRule extends Omit<WireUserRule, 'conditions' | 'actions'> {
	conditions: RuleCondition[];
	actions: RuleAction[];
}

/** The write shape the server accepts (mailboxId + isTransportRule are ignored server-side). */
export interface RuleInput {
	name: string;
	enabled: boolean;
	priority: number;
	runOn: RunOn;
	conditions: RuleCondition[];
	actions: RuleAction[];
	stopProcessing: boolean;
}

/** How far back an "apply to existing mail" sweep reaches. */
export type RetroWindow = components['schemas']['Rules.RetroWindow'];

export type ApplyRetroResult = components['schemas']['Rules.ApplyRetroResult'];

export type ApplyStatus = components['schemas']['Rules.ApplyStatus'];

// Preserve RFC 9457 problem+json detail on non-allowStatuses errors (e.g. plain 403).
const rulesEdgeClient = createEdgeClient({
	onError: (r) => problemDetail(r, `Rule request failed (${r.status})`)
});

function ruleFailure(error: unknown, response: Response): Error {
	return toEdgeProblemError(error, response, `Rule request failed (${response.status})`);
}

function normalizeRule(rule: WireUserRule): UserRule {
	return {
		...rule,
		conditions: rule.conditions ?? [],
		actions: rule.actions ?? []
	};
}

export async function listRules(signal?: AbortSignal): Promise<UserRule[]> {
	// -list suffix: the SPA page is at /settings/rules, so the GET list API must use a
	// disjoint path or it shadows the SPA on deep-link/refresh.
	const { data, error, response } = await rulesEdgeClient.GET('/api/settings/rules-list', {
		signal
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw ruleFailure(error, response);
	}
	return data.map(normalizeRule);
}

export async function createRule(input: RuleInput): Promise<number> {
	const { data, error, response } = await rulesEdgeClient.POST('/api/settings/rules', {
		body: input
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw ruleFailure(error, response);
	}
	return data.id;
}

export async function updateRule(id: number, input: RuleInput): Promise<void> {
	const { error, response } = await rulesEdgeClient.PUT('/api/settings/rules/{id}', {
		params: { path: { id } },
		body: input
	});
	if (!response.ok || error !== undefined) {
		throw ruleFailure(error, response);
	}
}

export async function deleteRule(id: number): Promise<void> {
	const { error, response } = await rulesEdgeClient.DELETE('/api/settings/rules/{id}', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined) {
		throw ruleFailure(error, response);
	}
}

/** Enqueue an async sweep applying this rule to existing mail (202 → action id). */
export async function applyRuleRetro(id: number, window: RetroWindow): Promise<ApplyRetroResult> {
	const { data, error, response } = await rulesEdgeClient.POST('/api/settings/rules/{id}/apply', {
		params: { path: { id } },
		body: { window }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw ruleFailure(error, response);
	}
	return data;
}

/** Poll the progress of a retro-apply sweep by its action id. */
export async function getApplyStatus(actionId: string, signal?: AbortSignal): Promise<ApplyStatus> {
	const { data, error, response } = await rulesEdgeClient.GET(
		'/api/settings/rules/apply/{actionId}',
		{
			params: { path: { actionId } },
			signal
		}
	);
	if (!response.ok || error !== undefined || data === undefined) {
		throw ruleFailure(error, response);
	}
	return data;
}
