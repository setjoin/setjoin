import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
	ALL_CAPTURE_SURFACES,
	DISK_HEADROOM_FACTOR,
	estimateRequiredBytes,
	nodeFreeDiskBytes,
	observedCaptureIdentity,
	runCapturePreflight,
	type CapturePreflight,
	type CapturePreflightResult,
	type CaptureSurfaceId,
	type PreflightDeps,
} from './preflight';
import { MEET_LOCAL_RECORDING_FLAG } from './rollout';

function makeDeps(overrides: Partial<PreflightDeps> = {}): PreflightDeps & { probeCounts: { capability: number; disk: number; permission: number } } {
	const probeCounts = { capability: 0, disk: 0, permission: 0 };
	return {
		probeCounts,
		identity: () => ({
			platform: 'darwin',
			platformVersion: '25.6.0',
			captureApiVersion: 'electron-43+chromium-143',
		}),
		surfacesSupported: () => {
			probeCounts.capability += 1;
			return ['microphone', 'systemAudio'];
		},
		freeDiskBytes: async () => {
			probeCounts.disk += 1;
			return 40 * 1024 ** 3;
		},
		permissionStatus: (surface) => {
			probeCounts.permission += 1;
			return surface === 'microphone' ? 'granted' : 'granted';
		},
		nowMs: () => 1_000,
		...overrides,
	};
}

function makeRequest(overrides: Record<string, unknown> = {}) {
	return {
		meetingId: 42,
		surfaces: ['microphone', 'systemAudio'] as CaptureSurfaceId[],
		plannedDurationMs: 60 * 60 * 1000,
		estimatedBitsPerSecond: 128_000,
		captureDir: '/tmp/setjoin-capture',
		...overrides,
	};
}

function asResult(preflight: CapturePreflight): CapturePreflightResult {
	if (preflight.kind !== 'result') throw new Error(`expected a result, got ${preflight.kind}`);
	return preflight;
}

describe('estimateRequiredBytes (fit-to-space honesty)', () => {
	it('estimates duration × bitrate with the documented headroom', () => {
		const hourAt128k = Math.ceil((3_600 * 128_000) / 8);
		expect(estimateRequiredBytes(3_600_000, 128_000)).toBe(Math.ceil(hourAt128k * DISK_HEADROOM_FACTOR));
	});

	it('never estimates for non-positive plans', () => {
		expect(estimateRequiredBytes(0, 128_000)).toBe(0);
		expect(estimateRequiredBytes(60_000, 0)).toBe(0);
		expect(estimateRequiredBytes(-1, 128_000)).toBe(0);
	});
});

describe('runCapturePreflight', () => {
	it('is INERT in rollout mode off: no probe runs and the refusal names the flag', async () => {
		const deps = makeDeps();
		const preflight = await runCapturePreflight('off', deps, makeRequest());
		expect(preflight).toEqual({
			kind: 'inert_flag_off',
			flag: MEET_LOCAL_RECORDING_FLAG,
			detail: expect.stringContaining(MEET_LOCAL_RECORDING_FLAG),
			ranAtUnixMs: 1_000,
		});
		expect(deps.probeCounts).toEqual({ capability: 0, disk: 0, permission: 0 });
	});

	it('admits a fully capable, space-rich, permitted capture in execute mode', async () => {
		const result = asResult(await runCapturePreflight('execute', makeDeps(), makeRequest()));
		expect(result.admitted).toBe(true);
		expect(result.actionRequired).toEqual([]);
		expect(result.identity).toEqual({
			platform: 'darwin',
			platformVersion: '25.6.0',
			captureApiVersion: 'electron-43+chromium-143',
		});
		expect(result.checks.map((c) => c.check)).toEqual(['capture_api', 'disk_space', 'permission', 'permission']);
		expect(result.checks.every((c) => c.status === 'available')).toBe(true);
	});

	it('runs read-only probes (but never admits capture) in observe mode', async () => {
		const result = asResult(await runCapturePreflight('observe', makeDeps(), makeRequest()));
		expect(result.admitted).toBe(true);
		expect(result.checks).toHaveLength(4);
	});

	it('treats insufficient disk as ACTION-REQUIRED with the honest byte math, never silent degradation', async () => {
		// 50 MiB free vs a ~72 MB requirement (1h × 128 kbit/s + headroom).
		const free = 50 * 1024 ** 2;
		const result = asResult(
			await runCapturePreflight('execute', makeDeps({ freeDiskBytes: async () => free }), makeRequest()),
		);
		expect(result.admitted).toBe(false);
		const disk = result.checks.find((c) => c.check === 'disk_space');
		expect(disk).toMatchObject({ status: 'action_required', freeBytes: free });
		if (disk?.check !== 'disk_space') throw new Error('wrong check');
		expect(disk.actionRequired).toContain('Free at least');
		expect(disk.actionRequired).toContain('or choose another capture directory');
		expect(result.actionRequired.length).toBeGreaterThan(0);
	});

	it('fails closed when the disk probe cannot prove anything (unknown, never assumed healthy)', async () => {
		const result = asResult(
			await runCapturePreflight('execute', makeDeps({ freeDiskBytes: async () => { throw new Error('EIO'); } }), makeRequest()),
		);
		expect(result.admitted).toBe(false);
		const disk = result.checks.find((c) => c.check === 'disk_space');
		expect(disk).toMatchObject({ status: 'unknown', freeBytes: null, headroomBytes: null });
		expect(result.actionRequired.join(' ')).toContain('could not be verified');
	});

	it('refuses capture when a requested surface is not capability-supported', async () => {
		const result = asResult(
			await runCapturePreflight(
				'execute',
				makeDeps({ surfacesSupported: () => ['microphone'] }),
				makeRequest(),
			),
		);
		expect(result.admitted).toBe(false);
		const capability = result.checks.find((c) => c.check === 'capture_api');
		expect(capability).toMatchObject({ status: 'unavailable', surfacesAvailable: ['microphone'] });
		expect(result.actionRequired.join(' ')).toContain('systemAudio');
	});

	it('fails closed when the capability probe itself errors', async () => {
		const result = asResult(
			await runCapturePreflight(
				'execute',
				makeDeps({ surfacesSupported: () => { throw new Error('boom'); } }),
				makeRequest(),
			),
		);
		expect(result.admitted).toBe(false);
		expect(result.checks.find((c) => c.check === 'capture_api')).toMatchObject({ status: 'unknown' });
	});

	it('maps each OS permission state to the typed action-required posture', async () => {
		const cases: Array<{ permission: string; expectedStatus: string }> = [
			{ permission: 'granted', expectedStatus: 'available' },
			{ permission: 'denied', expectedStatus: 'action_required' },
			{ permission: 'restricted', expectedStatus: 'action_required' },
			{ permission: 'not_determined', expectedStatus: 'action_required' },
			{ permission: 'unknown', expectedStatus: 'unknown' },
			{ permission: 'unavailable', expectedStatus: 'unknown' },
		];
		for (const c of cases) {
			const result = asResult(
				await runCapturePreflight(
					'execute',
					makeDeps({ permissionStatus: () => c.permission as never }),
					makeRequest({ surfaces: ['microphone'] }),
				),
			);
			const permission = result.checks.find((ch) => ch.check === 'permission');
			expect(permission, c.permission).toMatchObject({ status: c.expectedStatus, surface: 'microphone' });
			expect(result.admitted, c.permission).toBe(c.permission === 'granted');
		}
	});

	it('fails closed when a permission probe errors', async () => {
		const result = asResult(
			await runCapturePreflight(
				'execute',
				makeDeps({ permissionStatus: () => { throw new Error('no api'); } }),
				makeRequest({ surfaces: ['microphone'] }),
			),
		);
		expect(result.admitted).toBe(false);
		expect(result.checks.find((c) => c.check === 'permission')).toMatchObject({ status: 'unknown', permission: 'unknown' });
	});

	it('exposes the full surface vocabulary for callers that probe everything', () => {
		expect(ALL_CAPTURE_SURFACES).toEqual(['microphone', 'systemAudio']);
	});
});

describe('production node probes', () => {
	it('observes a version-pinned capture identity from the running runtime', () => {
		const identity = observedCaptureIdentity();
		expect(identity.platform).toBe(os.platform());
		expect(identity.platformVersion).toBe(os.release());
		// Under vitest there is no Electron runtime — the observation is
		// honestly 'unknown' there; under Electron main it pins real versions.
		expect(identity.captureApiVersion).toMatch(
			/^electron-(\d+|unknown)\+chromium-(\d+|unknown)$/,
		);
	});

	it('reports positive free bytes for a real directory', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-preflight-'));
		try {
			const free = await nodeFreeDiskBytes(dir);
			expect(free).toBeGreaterThan(0);
		} finally {
			fs.rmdirSync(dir);
		}
	});

	it('rejects a nonexistent path instead of inventing free space', async () => {
		await expect(nodeFreeDiskBytes('/nonexistent/setjoin-preflight-path')).rejects.toThrow();
	});
});
