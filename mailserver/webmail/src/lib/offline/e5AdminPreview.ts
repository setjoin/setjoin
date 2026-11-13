// E5 admin policy-preview controller (Phase 2 Design pass 7 + R4 settings
// amendments). The preview calls a SERVER authority for a selected user/device
// (POST /admin/offline/policy-preview — E1, auth-first) and the client only
// renders what the server resolved: winning policy id/scope, requested vs
// effective values, source per narrowed field, opt-in/approval. Disabled
// winning policies remain VISIBLE — never filtered out.
//
// Race contract (R4): every response binds the selected target AND the request
// generation. An older response can never replace a newer selection, a failed
// refresh labels retained facts stale, and unauthorized/unavailable are honest
// terminal states — the client never guesses.
export interface E5PreviewTarget {
	targetUserId: string;
	deviceId: string;
}

export interface E5PreviewPayload {
	mailboxId: string;
	deviceId: string;
	projection: E5PreviewProjection;
}

export interface E5PreviewProjection {
	allowed: boolean;
	approvalState: string;
	maxOfflineDays: number;
	syncMode: 'off' | 'observe' | 'execute';
	backgroundAllowed: boolean;
	requested: { automaticNetwork: string; attachmentPrefetch: string };
	effective: { automaticNetwork: string; attachmentPrefetch: string; opportunisticRequiresCharging: boolean };
	sources: {
		automaticNetwork?: { policyId?: string; scope?: string };
		attachmentPrefetch?: { policyId?: string; scope?: string };
	};
}

export type E5PreviewStatus =
	| { kind: 'idle' }
	| { kind: 'loading'; generation: number; target: E5PreviewTarget }
	| { kind: 'current'; generation: number; target: E5PreviewTarget; payload: E5PreviewPayload; stale: false }
	| { kind: 'unavailable'; generation: number; target: E5PreviewTarget; stale: boolean; retained: E5PreviewPayload | null }
	| { kind: 'unauthorized'; generation: number; target: E5PreviewTarget; stale: boolean; retained: E5PreviewPayload | null };

export type E5PreviewLoadResult =
	| { kind: 'applied' }
	| { kind: 'stale-generation' }
	| { kind: 'target-mismatch' }
	| { kind: 'malformed' };

/**
 * Strict parser for the E1 preview envelope `{mailboxId, deviceId, projection}`
 * — unknown shapes fail closed to null (never partially trusted).
 */
export function parsePreviewEnvelope(value: unknown): E5PreviewPayload | null {
	if (typeof value !== 'object' || value === null) return null;
	const envelope = value as Record<string, unknown>;
	if (typeof envelope.mailboxId !== 'string' || envelope.mailboxId.length === 0) return null;
	if (typeof envelope.deviceId !== 'string' || envelope.deviceId.length === 0) return null;
	const projection = parsePreviewProjection(envelope.projection);
	if (projection === null) return null;
	return { mailboxId: envelope.mailboxId, deviceId: envelope.deviceId, projection };
}

/**
 * Strict parser for the offline_effective_policy_snapshot projection. Winning
 * DISABLED policies are preserved in `sources` — visibility is never narrowed
 * by enablement.
 */
export function parsePreviewProjection(value: unknown): E5PreviewProjection | null {
	if (typeof value !== 'object' || value === null) return null;
	const raw = value as Record<string, unknown>;
	const qos = raw.syncQoS;
	if (typeof qos !== 'object' || qos === null) return null;
	const q = qos as Record<string, unknown>;
	if (q.schemaVersion !== 1) return null;
	if (q.mode !== 'off' && q.mode !== 'observe' && q.mode !== 'execute') return null;
	if (typeof q.backgroundAllowed !== 'boolean') return null;
	const requested = q.requested;
	const effective = q.effective;
	if (typeof requested !== 'object' || requested === null || typeof effective !== 'object' || effective === null) return null;
	const req = requested as Record<string, unknown>;
	const eff = effective as Record<string, unknown>;
	if (
		(req.automaticNetwork !== 'never' && req.automaticNetwork !== 'unmetered' && req.automaticNetwork !== 'any')
		|| (req.attachmentPrefetch !== 'never' && req.attachmentPrefetch !== 'unmetered' && req.attachmentPrefetch !== 'always')
		|| (eff.automaticNetwork !== 'never' && eff.automaticNetwork !== 'unmetered' && eff.automaticNetwork !== 'any')
		|| (eff.attachmentPrefetch !== 'never' && eff.attachmentPrefetch !== 'unmetered' && eff.attachmentPrefetch !== 'always')
		|| typeof eff.opportunisticRequiresCharging !== 'boolean'
	) return null;
	if (typeof raw.allowed !== 'boolean' || typeof raw.approvalState !== 'string' || typeof raw.maxOfflineDays !== 'number') return null;

	const sources: E5PreviewProjection['sources'] = {};
	const rawSources = q.sources;
	if (rawSources !== undefined) {
		if (typeof rawSources !== 'object' || rawSources === null) return null;
		const s = rawSources as Record<string, unknown>;
		const parseSource = (input: unknown): { policyId?: string; scope?: string } | undefined => {
			if (input === undefined) return undefined;
			if (typeof input !== 'object' || input === null) return undefined;
			const record = input as Record<string, unknown>;
			const out: { policyId?: string; scope?: string } = {};
			if (record.policyId !== undefined) {
				if (typeof record.policyId !== 'string') return undefined;
				out.policyId = record.policyId;
			}
			if (record.scope !== undefined) {
				if (typeof record.scope !== 'string') return undefined;
				out.scope = record.scope;
			}
			return out;
		};
		const automaticNetwork = parseSource(s.automaticNetwork);
		const attachmentPrefetch = parseSource(s.attachmentPrefetch);
		if (automaticNetwork) sources.automaticNetwork = automaticNetwork;
		if (attachmentPrefetch) sources.attachmentPrefetch = attachmentPrefetch;
	}

	return {
		allowed: raw.allowed,
		approvalState: raw.approvalState,
		maxOfflineDays: raw.maxOfflineDays,
		syncMode: q.mode,
		backgroundAllowed: q.backgroundAllowed,
		requested: { automaticNetwork: req.automaticNetwork, attachmentPrefetch: req.attachmentPrefetch },
		effective: {
			automaticNetwork: eff.automaticNetwork,
			attachmentPrefetch: eff.attachmentPrefetch,
			opportunisticRequiresCharging: eff.opportunisticRequiresCharging,
		},
		sources,
	};
}

export interface E5AdminPreviewController {
	/** Select a target (or re-select). Any change bumps the generation so an
	 * older response can never replace the newer selection. */
	selectTarget(target: E5PreviewTarget): void;
	/** Resolve a load. Applied ONLY at the current generation AND when the
	 * payload's device identity matches the selected target. */
	loaded(generation: number, payload: unknown): E5PreviewLoadResult;
	/** Fail a load: 403/BZ002-class → unauthorized; anything else → unavailable.
	 * Previously retained facts stay visible but labeled stale. */
	failed(generation: number, error: { forbidden?: boolean }): void;
	status(): E5PreviewStatus;
	readonly generation: number;
}

export function createAdminPreviewController(): E5AdminPreviewController {
	let generation = 0;
	let target: E5PreviewTarget | null = null;
	let status: E5PreviewStatus = { kind: 'idle' };
	let retained: E5PreviewPayload | null = null;

	return {
		get generation(): number { return generation; },
		selectTarget(next: E5PreviewTarget): void {
			// Re-selecting the SAME target while a request is already in flight
			// coalesces (no churn); selecting it from any settled state is a
			// REFRESH — a new generation the old response can never satisfy.
			if (
				status.kind === 'loading'
				&& target !== null
				&& target.targetUserId === next.targetUserId
				&& target.deviceId === next.deviceId
			) return;
			target = { ...next };
			generation += 1;
			status = { kind: 'loading', generation, target: { ...next } };
		},
		loaded(atGeneration: number, payload: unknown): E5PreviewLoadResult {
			if (atGeneration !== generation || target === null) return { kind: 'stale-generation' };
			const parsed = parsePreviewEnvelope(payload);
			if (parsed === null) return { kind: 'malformed' };
			// Identity binding: the response must belong to the selected target.
			if (parsed.deviceId !== target.deviceId) return { kind: 'target-mismatch' };
			retained = parsed;
			status = { kind: 'current', generation: atGeneration, target: { ...target }, payload: parsed, stale: false };
			return { kind: 'applied' };
		},
		failed(atGeneration: number, error: { forbidden?: boolean }): void {
			if (atGeneration !== generation || target === null) return;
			status = error.forbidden === true
				? { kind: 'unauthorized', generation: atGeneration, target: { ...target }, stale: retained !== null, retained }
				: { kind: 'unavailable', generation: atGeneration, target: { ...target }, stale: retained !== null, retained };
		},
		status(): E5PreviewStatus { return status; },
	};
}
