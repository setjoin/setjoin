// End-user mail-rules client — the 4 security-scoped /settings/rules routes.
// Mirrors the delivery.ts fetch style (httpRequest seam; auth cookie automatic).
// The gateway forces the caller's own primary mailbox + non-transport, so we
// never send mailboxId/isTransportRule.

import { httpRequest } from '$lib/http';
import { problemDetail } from '$lib/errors';

/** A simple rule-engine condition (mirrors eval_condition in rule_engine.sql). */
export interface RuleCondition {
	field: string; // from_addr | subject | body | spam_score | size_bytes | has_attachments | sender_domain
	op: string; // contains | equals | starts_with | matches_regex | in_list | gt | lt | ...
	value: string;
}

/** A rule-engine action (mirrors apply_action in rule_engine.sql). */
export interface RuleAction {
	type: string; // move_to | flag | mark_read | categorize | delete | forward_to | add_header | bcc | append_footer | redirect
	params?: Record<string, string>;
}

export type RunOn = 'server' | 'client' | 'both';

export interface UserRule {
	id: number;
	mailboxId: number;
	name: string;
	enabled: boolean;
	priority: number;
	runOn: RunOn;
	isTransportRule: boolean;
	conditions: RuleCondition[];
	actions: RuleAction[];
	stopProcessing: boolean;
	createdAt: string;
	updatedAt: string;
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

const JSON_HEADERS = { 'content-type': 'application/json' };

// Surface the reducer's problem+json detail for the caller's own rules (low-risk surface).
const ruleError = (r: Response) => problemDetail(r, `Rule request failed (${r.status})`);

export async function listRules(signal?: AbortSignal): Promise<UserRule[]> {
	// -list suffix: the SPA page is at /settings/rules, so the GET list API must use a
	// disjoint path or it shadows the SPA on deep-link/refresh (see main.go + b8a94e30).
	const res = await httpRequest('/api/settings/rules-list', { method: 'GET', signal, onError: ruleError });
	return (await res.json()) as UserRule[];
}

export async function createRule(input: RuleInput): Promise<number> {
	const res = await httpRequest('/api/settings/rules', {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify(input),
		onError: ruleError
	});
	const body = (await res.json()) as { id: number };
	return body.id;
}

export async function updateRule(id: number, input: RuleInput): Promise<void> {
	await httpRequest(`/api/settings/rules/${id}`, {
		method: 'PUT',
		headers: JSON_HEADERS,
		body: JSON.stringify(input),
		onError: ruleError
	});
}

export async function deleteRule(id: number): Promise<void> {
	await httpRequest(`/api/settings/rules/${id}`, { method: 'DELETE', onError: ruleError });
}

/** How far back an "apply to existing mail" sweep reaches. */
export type RetroWindow = '90d' | '1y' | 'all';

export interface ApplyRetroResult {
	actionId: string;
	status: string; // 'queued'
}

export interface ApplyStatus {
	status: 'pending' | 'processing' | 'done' | 'failed';
	processed?: number; // populated once the sweep completes
	truncated?: boolean; // true when the window exceeded the server cap
}

/** Enqueue an async sweep applying this rule to existing mail (202 → action id). */
export async function applyRuleRetro(id: number, window: RetroWindow): Promise<ApplyRetroResult> {
	const res = await httpRequest(`/api/settings/rules/${id}/apply`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ window }),
		onError: ruleError
	});
	return (await res.json()) as ApplyRetroResult;
}

/** Poll the progress of a retro-apply sweep by its action id. */
export async function getApplyStatus(actionId: string, signal?: AbortSignal): Promise<ApplyStatus> {
	const res = await httpRequest(`/api/settings/rules/apply/${encodeURIComponent(actionId)}`, {
		method: 'GET',
		signal,
		onError: ruleError
	});
	return (await res.json()) as ApplyStatus;
}
