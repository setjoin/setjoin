import { describe, expect, it } from 'vitest';

import {
	emptyShellGenerationState,
	candidateExpired,
	reduceShellGenerationState,
	retainedCacheNames,
	retainedMemberBuilds,
	validateCriticalShellManifest,
} from './sw-generation';

const hash = 'a'.repeat(64);

describe('critical shell manifest validation', () => {
	it('accepts an exact same-origin build-scoped member list', () => {
		const manifest = validateCriticalShellManifest({
			schemaVersion: 1,
			protocolVersion: 1,
			buildId: 'b1',
			members: [{ path: '/index.html', identityBytes: 10, sha256: hash }],
		}, 'b1', 'https://mail.example.com');
		expect(manifest?.members[0].path).toBe('/index.html');
	});

	it.each([
		['wrong build', { schemaVersion: 1, protocolVersion: 1, buildId: 'old', members: [{ path: '/index.html', identityBytes: 10, sha256: hash }] }],
		['external URL', { schemaVersion: 1, protocolVersion: 1, buildId: 'b1', members: [{ path: 'https://evil.invalid/x.js', identityBytes: 10, sha256: hash }] }],
		['query token', { schemaVersion: 1, protocolVersion: 1, buildId: 'b1', members: [{ path: '/x.js?token=secret', identityBytes: 10, sha256: hash }] }],
		['service worker', { schemaVersion: 1, protocolVersion: 1, buildId: 'b1', members: [{ path: '/service-worker.js', identityBytes: 10, sha256: hash }] }],
		['duplicate', { schemaVersion: 1, protocolVersion: 1, buildId: 'b1', members: [{ path: '/x.js', identityBytes: 10, sha256: hash }, { path: '/x.js', identityBytes: 10, sha256: hash }] }],
		['bad hash', { schemaVersion: 1, protocolVersion: 1, buildId: 'b1', members: [{ path: '/x.js', identityBytes: 10, sha256: 'nope' }] }],
	])('rejects %s evidence', (_name, value) => {
		expect(validateCriticalShellManifest(value, 'b1', 'https://mail.example.com')).toBeNull();
	});
});

describe('shell generation state', () => {
	it('promotes only the exact candidate and retains one acknowledged previous generation', () => {
		let state = reduceShellGenerationState(emptyShellGenerationState(), { type: 'installed', buildId: 'b1', members: ['/index.html'] });
		state = reduceShellGenerationState(state, { type: 'activated', buildId: 'b1', activatedAtMs: 10 });
		state = reduceShellGenerationState(state, { type: 'mounted', buildId: 'wrong' });
		expect(state.currentBuildId).toBeNull();
		state = reduceShellGenerationState(state, { type: 'mounted', buildId: 'b1' });
		state = reduceShellGenerationState(state, { type: 'installed', buildId: 'b2', members: ['/index.html', '/b2.js'] });
		state = reduceShellGenerationState(state, { type: 'activated', buildId: 'b2', activatedAtMs: 20 });
		state = reduceShellGenerationState(state, { type: 'mounted', buildId: 'b2' });
		expect(state.currentBuildId).toBe('b2');
		expect(state.previousBuildId).toBe('b1');
		expect(state.generations.b2.acknowledged).toBe(true);
		expect([...retainedCacheNames(state)].sort()).toEqual(['setjoin-shell-v1-b1', 'setjoin-shell-v1-b2']);
		expect(retainedMemberBuilds(state, '/index.html')).toEqual(['b2', 'b1']);
	});

	it('marks an unmounted candidate failed without replacing the acknowledged current build', () => {
		let state = reduceShellGenerationState(emptyShellGenerationState(), { type: 'installed', buildId: 'b1', members: ['/index.html'] });
		state = reduceShellGenerationState(state, { type: 'activated', buildId: 'b1', activatedAtMs: 10 });
		state = reduceShellGenerationState(state, { type: 'mounted', buildId: 'b1' });
		state = reduceShellGenerationState(state, { type: 'installed', buildId: 'b2', members: ['/index.html'] });
		state = reduceShellGenerationState(state, { type: 'activated', buildId: 'b2', activatedAtMs: 20 });
		state = reduceShellGenerationState(state, { type: 'failed', buildId: 'b2' });
		expect(state.currentBuildId).toBe('b1');
		expect(state.failedBuildId).toBe('b2');
		expect(state.candidateBuildId).toBeNull();
		expect(state.generations.b2).toBeUndefined();
	});

	it('starts expiry at activation, persists it across worker termination, and rejects clock rollback', () => {
		let state = reduceShellGenerationState(emptyShellGenerationState(), {
			type: 'installed', buildId: 'b1', members: ['/index.html'],
		});
		expect(candidateExpired(state, 100_000, 15_000)).toBe(true);
		state = reduceShellGenerationState(state, { type: 'activated', buildId: 'b1', activatedAtMs: 1_000 });
		expect(candidateExpired(state, 15_999, 15_000)).toBe(false);
		expect(candidateExpired(state, 16_000, 15_000)).toBe(true);
		expect(candidateExpired(state, 999, 15_000)).toBe(true);
	});

	it('does not mount an installed candidate before activation evidence exists', () => {
		let state = reduceShellGenerationState(emptyShellGenerationState(), {
			type: 'installed', buildId: 'b1', members: ['/index.html'],
		});
		state = reduceShellGenerationState(state, { type: 'mounted', buildId: 'b1' });
		expect(state.currentBuildId).toBeNull();
		expect(state.candidateBuildId).toBe('b1');
	});
});
