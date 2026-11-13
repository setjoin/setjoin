// E5 settings controller (Phase 2 Design pass 1 + R4 settings amendments).
//
// - Requested drafts stay DISTINCT from acknowledged effective values; only an
//   authoritative response updates the effective state. The client NEVER
//   recomputes policy precedence ("no client-side policy resolver").
// - A pending save prevents duplicate submission; failure preserves the drafts
//   and surfaces a remedy — never a success; account/device changes invalidate
//   pending responses (an in-flight reply for an old binding can never land).
// - Wire enums stay scoped exactly as E1 shipped them: `any` for refresh,
//   `always` for attachments.
//
// Pure module: the page wires the loaders/savers; OFF-gate default keeps every
// existing surface unchanged.
export const AUTOMATIC_NETWORK_VALUES = ['never', 'unmetered', 'any'] as const;
export type E5AutomaticNetworkPref = (typeof AUTOMATIC_NETWORK_VALUES)[number];

export const ATTACHMENT_PREFETCH_VALUES = ['never', 'unmetered', 'always'] as const;
export type E5AttachmentPrefetchPref = (typeof ATTACHMENT_PREFETCH_VALUES)[number];

/** What the user asked for (device preferences). */
export interface E5RequestedPrefs {
	backgroundSyncEnabled: boolean;
	automaticNetwork: E5AutomaticNetworkPref;
	attachmentPrefetch: E5AttachmentPrefetchPref;
}

/** What the server resolved (never client-computed). */
export interface E5EffectivePrefs {
	backgroundAllowed: boolean;
	automaticNetwork: E5AutomaticNetworkPref;
	attachmentPrefetch: E5AttachmentPrefetchPref;
	opportunisticRequiresCharging: boolean;
}

/** Server-provided source/reason per narrowed field (admin preview shape). */
export interface E5PrefFieldSource {
	policyId?: string;
	scope?: string;
}

export interface E5AcknowledgeSnapshot {
	requested: E5RequestedPrefs;
	effective: E5EffectivePrefs;
	sources: { automaticNetwork?: E5PrefFieldSource; attachmentPrefetch?: E5PrefFieldSource };
}

export type E5SaveRemedyKey = 'offline.e5.settings.remedy_retry' | 'offline.e5.settings.remedy_sign_in';

export type E5SaveOutcome =
	| { ok: true; snapshot: E5AcknowledgeSnapshot }
	| { ok: false; reason: 'duplicate-submission' | 'save-failed' | 'stale-binding'; remedyKey?: E5SaveRemedyKey };

export type E5SettingsStatus =
	| { kind: 'idle' }
	| { kind: 'pending'; generation: number }
	| { kind: 'saved'; generation: number }
	| { kind: 'failed'; generation: number; remedyKey?: E5SaveRemedyKey };

export interface E5SettingsView {
	/** The user's current drafts (may differ from acknowledged requested). */
	draft: E5RequestedPrefs;
	/** The last authoritative snapshot, if any. */
	acknowledged: E5AcknowledgeSnapshot | null;
	status: E5SettingsStatus;
	/** True when the draft differs from the acknowledged requested values. */
	dirty: boolean;
	/** A save is in flight — controls stay disabled against duplicate submits. */
	pending: boolean;
}

export interface E5SettingsSaver {
	/** Resolves with the authoritative post-save snapshot from the server. */
	(generation: number, requested: E5RequestedPrefs): Promise<E5AcknowledgeSnapshot>;
}

export function createE5SettingsController(initial: E5RequestedPrefs = {
	backgroundSyncEnabled: false,
	automaticNetwork: 'unmetered',
	attachmentPrefetch: 'never',
}) {
	let draft: E5RequestedPrefs = { ...initial };
	let acknowledged: E5AcknowledgeSnapshot | null = null;
	let status: E5SettingsStatus = { kind: 'idle' };
	let generation = 0;
	let boundAccountId: string | null = null;
	let boundDeviceId: string | null = null;

	function prefsEqual(a: E5RequestedPrefs, b: E5RequestedPrefs): boolean {
		return a.backgroundSyncEnabled === b.backgroundSyncEnabled
			&& a.automaticNetwork === b.automaticNetwork
			&& a.attachmentPrefetch === b.attachmentPrefetch;
	}

	return {
		/** Bind (or re-bind) the owning account/device. Any change invalidates a
		 * pending response (an in-flight reply for the old binding can never
		 * update this controller's effective state) AND retires the previous
		 * binding's acknowledged values — drafts reset to the defaults until an
		 * authoritative snapshot for the NEW binding arrives.
		 * deviceId is the REAL lifecycle identity (native secure store
		 * 'device_id') or null when this client has none (plain browser) —
		 * never a placeholder constant. */
		bindAccount(accountId: string, deviceId: string | null): boolean {
			if (boundAccountId === accountId && boundDeviceId === deviceId) return false;
			const firstBinding = boundAccountId === null;
			boundAccountId = accountId;
			boundDeviceId = deviceId;
			generation += 1; // in-flight responses are now stale
			status = { kind: 'idle' };
			if (firstBinding) return true; // keep any pre-binding acknowledged snapshot
			acknowledged = null;
			draft = { ...initial };
			return true;
		},
		get accountId(): string | null { return boundAccountId; },
		get deviceId(): string | null { return boundDeviceId; },
		/** Only an authoritative snapshot updates the acknowledged state. */
		acknowledge(snapshot: E5AcknowledgeSnapshot): void {
			acknowledged = {
				requested: { ...snapshot.requested },
				effective: { ...snapshot.effective },
				sources: { ...snapshot.sources },
			};
			draft = { ...snapshot.requested };
			if (status.kind === 'pending' || status.kind === 'failed') status = { kind: 'idle' };
		},
		edit(patch: Partial<E5RequestedPrefs>): void {
			if (status.kind === 'pending') return; // edits stay possible but do not mutate a submitting draft
			draft = { ...draft, ...patch };
			if (status.kind === 'saved') status = { kind: 'idle' };
		},
		view(): E5SettingsView {
			return {
				draft: { ...draft },
				acknowledged,
				status,
				dirty: acknowledged === null || !prefsEqual(draft, acknowledged.requested),
				pending: status.kind === 'pending',
			};
		},
		/** Duplicate submission is refused without touching the in-flight save. */
		async submit(saver: E5SettingsSaver): Promise<E5SaveOutcome> {
			if (status.kind === 'pending') return { ok: false, reason: 'duplicate-submission' };
			generation += 1;
			const thisGeneration = generation;
			const submitted: E5RequestedPrefs = { ...draft };
			status = { kind: 'pending', generation: thisGeneration };
			try {
				const snapshot = await saver(thisGeneration, submitted);
				if (generation !== thisGeneration) {
					// The binding changed mid-flight: the response is invalid.
					return { ok: false, reason: 'stale-binding' };
				}
				acknowledged = {
					requested: { ...snapshot.requested },
					effective: { ...snapshot.effective },
					sources: { ...snapshot.sources },
				};
				draft = { ...snapshot.requested };
				status = { kind: 'saved', generation: thisGeneration };
				return { ok: true, snapshot: acknowledged };
			} catch {
				if (generation !== thisGeneration) return { ok: false, reason: 'stale-binding' };
				// FAILURE: drafts are preserved, a remedy is surfaced, and the
				// acknowledged state is untouched — never a success.
				status = { kind: 'failed', generation: thisGeneration, remedyKey: 'offline.e5.settings.remedy_retry' };
				return { ok: false, reason: 'save-failed', remedyKey: 'offline.e5.settings.remedy_retry' };
			}
		},
	};
}

export type E5SettingsController = ReturnType<typeof createE5SettingsController>;

// ── Crossed network/attachment explanation (CAS-E5-CROSSED-NETWORK-ATTACHMENT) ──

export interface E5CrossedAdmissionInput {
	backgroundSyncEnabled: boolean;
	/** Server-resolved effective values — the client never recomputes them. */
	effectiveAutomaticNetwork: E5AutomaticNetworkPref;
	effectiveAttachmentPrefetch: E5AttachmentPrefetchPref;
	/** Current link cost as reported by capability truth (browser: unknown → false). */
	meteredLink: boolean;
}

export interface E5CrossedAdmissionExplanation {
	backgroundKey: string | null;
	refreshKey: string;
	attachmentKey: string;
	linkKey: string | null;
}

/**
 * Explain ACTUAL admission from the stored values. `Background sync=Off`
 * disables automatic work regardless of the network preferences, but the
 * explanation must never promise "all network disabled": explicit actions and
 * the other preference's own limit still apply. Refresh Never does not imply
 * attachment Never, and vice versa.
 */
export function explainCrossedAdmission(input: E5CrossedAdmissionInput): E5CrossedAdmissionExplanation {
	const backgroundKey = input.backgroundSyncEnabled
		? null
		: 'offline.e5.settings.crossed.background_off';
	const refreshKey = input.effectiveAutomaticNetwork === 'never'
		? 'offline.e5.settings.crossed.refresh_never'
		: input.meteredLink && input.effectiveAutomaticNetwork === 'unmetered'
			? 'offline.e5.settings.crossed.refresh_metered_wait'
			: 'offline.e5.settings.crossed.refresh_on';
	const attachmentKey = input.effectiveAttachmentPrefetch === 'never'
		? 'offline.e5.settings.crossed.attachment_never'
		: input.meteredLink && input.effectiveAttachmentPrefetch === 'unmetered'
			? 'offline.e5.settings.crossed.attachment_metered_wait'
			: 'offline.e5.settings.crossed.attachment_on';
	const linkKey = input.meteredLink ? 'offline.e5.settings.crossed.link_metered' : null;
	return { backgroundKey, refreshKey, attachmentKey, linkKey };
}
