export const SHELL_PROTOCOL_VERSION = 1 as const;
export const SHELL_MANIFEST_PATH = '/critical-shell.v1.json';
export const SHELL_CACHE_PREFIX = 'setjoin-shell-v1-';
export const SHELL_STATE_CACHE = 'setjoin-shell-state-v1';
export const SHELL_STATE_KEY = '/__setjoin/service-worker-generation-state-v1';

export interface CriticalShellMember {
	path: string;
	identityBytes: number;
	sha256: string;
}

export interface CriticalShellManifest {
	schemaVersion: 1;
	protocolVersion: 1;
	buildId: string;
	members: CriticalShellMember[];
}

export interface RetainedShellGeneration {
	buildId: string;
	members: string[];
	acknowledged: boolean;
}

export interface ShellGenerationState {
	protocolVersion: 1;
	currentBuildId: string | null;
	previousBuildId: string | null;
	candidateBuildId: string | null;
	candidateActivatedAtMs: number | null;
	failedBuildId: string | null;
	generations: Record<string, RetainedShellGeneration>;
}

export type ShellGenerationEvent =
	| { type: 'installed'; buildId: string; members: string[] }
	| { type: 'activated'; buildId: string; activatedAtMs: number }
	| { type: 'mounted'; buildId: string }
	| { type: 'failed'; buildId: string };

export function emptyShellGenerationState(): ShellGenerationState {
	return {
		protocolVersion: SHELL_PROTOCOL_VERSION,
		currentBuildId: null,
		previousBuildId: null,
		candidateBuildId: null,
		candidateActivatedAtMs: null,
		failedBuildId: null,
		generations: {},
	};
}

export function shellCacheName(buildId: string): string {
	return `${SHELL_CACHE_PREFIX}${buildId}`;
}

export function normalizePublicPath(input: string, origin = 'https://setjoin.invalid'): string | null {
	try {
		const url = new URL(input, origin);
		if (url.origin !== new URL(origin).origin || url.username || url.password || url.search || url.hash) return null;
		if (!url.pathname.startsWith('/') || url.pathname.includes('\\') || url.pathname.split('/').includes('..')) return null;
		return url.pathname;
	} catch {
		return null;
	}
}

export function validateCriticalShellManifest(
	value: unknown,
	expectedBuildId: string,
	origin: string,
): CriticalShellManifest | null {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
	const candidate = value as Partial<CriticalShellManifest>;
	if (
		candidate.schemaVersion !== 1 ||
		candidate.protocolVersion !== SHELL_PROTOCOL_VERSION ||
		candidate.buildId !== expectedBuildId ||
		!Array.isArray(candidate.members) ||
		candidate.members.length === 0
	) return null;
	const seen = new Set<string>();
	const members: CriticalShellMember[] = [];
	for (const raw of candidate.members) {
		if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
		const member = raw as Partial<CriticalShellMember>;
		const path = typeof member.path === 'string' ? normalizePublicPath(member.path, origin) : null;
		if (
			!path ||
			path === SHELL_MANIFEST_PATH ||
			path === '/service-worker.js' ||
			seen.has(path) ||
			!Number.isSafeInteger(member.identityBytes) ||
			(member.identityBytes ?? -1) < 0 ||
			typeof member.sha256 !== 'string' ||
			!/^[a-f0-9]{64}$/.test(member.sha256)
		) return null;
		seen.add(path);
		members.push({ path, identityBytes: member.identityBytes!, sha256: member.sha256 });
	}
	return { schemaVersion: 1, protocolVersion: 1, buildId: expectedBuildId, members };
}

function retainedIds(state: ShellGenerationState): Set<string> {
	return new Set([state.currentBuildId, state.previousBuildId, state.candidateBuildId].filter((id): id is string => Boolean(id)));
}

export function reduceShellGenerationState(
	input: ShellGenerationState,
	event: ShellGenerationEvent,
): ShellGenerationState {
	const state: ShellGenerationState = {
		...input,
		generations: Object.fromEntries(Object.entries(input.generations).map(([id, generation]) => [id, { ...generation, members: [...generation.members] }])),
	};
	if (event.type === 'installed') {
		state.candidateBuildId = event.buildId;
		state.candidateActivatedAtMs = null;
		state.failedBuildId = state.failedBuildId === event.buildId ? null : state.failedBuildId;
		state.generations[event.buildId] = {
			buildId: event.buildId,
			members: [...new Set(event.members)].sort(),
			acknowledged: state.currentBuildId === event.buildId,
		};
	} else if (event.type === 'activated' && state.candidateBuildId === event.buildId) {
		if (!Number.isFinite(state.candidateActivatedAtMs)) state.candidateActivatedAtMs = event.activatedAtMs;
	} else if (
		event.type === 'mounted' &&
		state.candidateBuildId === event.buildId &&
		Number.isFinite(state.candidateActivatedAtMs)
	) {
		if (state.currentBuildId && state.currentBuildId !== event.buildId) state.previousBuildId = state.currentBuildId;
		state.currentBuildId = event.buildId;
		state.candidateBuildId = null;
		state.candidateActivatedAtMs = null;
		state.failedBuildId = null;
		const generation = state.generations[event.buildId];
		if (generation) generation.acknowledged = true;
	} else if (event.type === 'failed' && state.candidateBuildId === event.buildId) {
		state.candidateBuildId = null;
		state.candidateActivatedAtMs = null;
		state.failedBuildId = event.buildId;
	}
	const keep = retainedIds(state);
	state.generations = Object.fromEntries(Object.entries(state.generations).filter(([id]) => keep.has(id)));
	return state;
}

export function candidateExpired(state: ShellGenerationState, nowMs: number, timeoutMs: number): boolean {
	if (!state.candidateBuildId) return false;
	if (!Number.isFinite(nowMs) || !Number.isFinite(timeoutMs) || timeoutMs < 0) return true;
	const activatedAt = state.candidateActivatedAtMs;
	if (activatedAt === null || !Number.isFinite(activatedAt)) return true;
	const elapsed = nowMs - activatedAt;
	return elapsed < 0 || elapsed >= timeoutMs;
}

export function retainedMemberBuilds(state: ShellGenerationState, path: string): string[] {
	const normalized = normalizePublicPath(path);
	if (!normalized) return [];
	return [state.candidateBuildId, state.currentBuildId, state.previousBuildId]
		.filter((id): id is string => Boolean(id))
		.filter((id, index, ids) => ids.indexOf(id) === index)
		.filter((id) => state.generations[id]?.members.includes(normalized));
}

export function retainedCacheNames(state: ShellGenerationState): Set<string> {
	return new Set([...retainedIds(state)].map(shellCacheName));
}
