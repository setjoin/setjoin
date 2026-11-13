//! MEET M5 slice 2 — the composition wiring's tests. The substrate modules
//! (preflight/consent/heartbeat/registration/rollout) pin their own
//! guarantees; this suite pins what the WIRING adds: the inertness matrix
//! under the shipped default `off` (no probes, no store reads, no transport
//! calls — the wire only activates in `execute`), the non-dismissible
//! consent gate ahead of any server call, the fail-closed transport (no
//! admitted origin or no session credential ⇒ no wire), and the
//! device-id mint-once contract under the renderer-denied namespace.

import { describe, it, expect, vi, afterEach } from 'vitest';

import type { NativeBinding } from '../native';
import {
	makeFetchMeetTransport,
	makeMeetLocalCaptureHandlers,
	meetCaptureDeviceId,
	MEET_LOCAL_CAPTURE_CONSENT_KEY,
	MEET_LOCAL_CAPTURE_DEVICE_KEY,
	type MeetServerTransport,
} from './localCapture';
import type { PreflightDeps } from './preflight';
import { DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE } from './rollout';

function fakeNative(over: Partial<NativeBinding> = {}): NativeBinding {
	const store = new Map<string, string>();
	return {
		vaultUnlock: () => true,
		vaultIsUnlocked: () => true,
		vaultListTotp: () => [],
		vaultGenerateTotp: () => '000000',
		secureStoreGet: vi.fn((key: string) => store.get(key) ?? null),
		secureStoreSet: vi.fn((key: string, value: string) => void store.set(key, value)),
		secureStoreRemove: vi.fn(),
		dbOpen: () => {},
		dbIsOpen: () => true,
		dbExec: () => 0,
		dbExecSchemaInit: () => 0,
		dbQuery: () => '[]',
		dbWipe: () => {},
		driveImportFile: async () => '{}',
		driveFetchChunk: async () => {},
		drivePushChunk: async () => 200,
		driveHasChunk: () => true,
		driveDeleteChunks: () => 0,
		driveSetConfinement: () => {},
		driveServeStart: async () => '{"port":1}',
		driveServeGrant: () => '/t/x',
		driveServeRevoke: () => {},
		driveServeStop: () => {},
		mamStoreDeviceId: () => {},
		mamStorePolicy: () => {},
		mamGetPolicy: () => null,
		mamMarkWiped: () => {},
		mamIsWiped: () => false,
		mamClearWiped: () => {},
		...over,
	} as NativeBinding;
}

/** Probes that fail LOUDLY — an inert composition must never call them. */
function loudPreflightDeps(): PreflightDeps {
	return {
		identity: () => {
			throw new Error('probe must not run while inert');
		},
		surfacesSupported: () => {
			throw new Error('probe must not run while inert');
		},
		freeDiskBytes: async () => {
			throw new Error('probe must not run while inert');
		},
		permissionStatus: () => {
			throw new Error('probe must not run while inert');
		},
		nowMs: () => 1000,
	};
}

function noTransport(): MeetServerTransport {
	return { postMeet: vi.fn(async () => { throw new Error('transport must not be called while inert'); }) };
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('meet local capture composition — inert under the shipped default off', () => {
	it('the shipped default is off (the composition root must not widen it)', () => {
		expect(DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE).toBe('off');
	});

	it('preflight returns the inert variant without calling any probe', async () => {
		const native = fakeNative();
		const h = makeMeetLocalCaptureHandlers({
			native,
			transport: noTransport(),
			preflightDeps: loudPreflightDeps(),
		});
		const result = (await h.meet_local_preflight({
			meetingId: 5,
			surfaces: ['microphone'],
			plannedDurationMs: 60_000,
			estimatedBitsPerSecond: 64_000,
			captureDir: '/tmp/capture',
		})) as { kind: string; flag: string };
		expect(result.kind).toBe('inert_flag_off');
		expect(result.flag).toBe('feature.meet_local_recording');
	});

	it('consent loading never reads the store and every transition refuses', async () => {
		const native = fakeNative();
		const h = makeMeetLocalCaptureHandlers({
			native,
			transport: noTransport(),
			preflightDeps: loudPreflightDeps(),
		});
		const grant = (await h.meet_local_consent_grant({ meetingId: 5, surfaces: ['microphone'] })) as {
			ok: boolean;
			refusal: string;
		};
		expect(grant.ok).toBe(false);
		expect(grant.refusal).toContain('feature.meet_local_recording');
		expect(native.secureStoreGet).not.toHaveBeenCalled();
		expect(native.secureStoreSet).not.toHaveBeenCalled();
	});

	it('every wire handler refuses without any transport call', async () => {
		const native = fakeNative();
		const transport = noTransport();
		const h = makeMeetLocalCaptureHandlers({
			native,
			transport,
			preflightDeps: loudPreflightDeps(),
		});
		for (const [channel, args] of [
			['meet_local_heartbeat', { meetingId: 5, recordingId: 9, seq: 1, leaseGeneration: 1 }],
			['meet_local_stop', { meetingId: 5, recordingId: 9 }],
			['meet_local_register', { meetingId: 5, recordingId: 9, descriptor: {} }],
		] as const) {
			const result = (await (h[channel] as (a: unknown) => Promise<unknown>)(args)) as {
				ok: false;
				refusal: string;
			};
			expect(result.ok).toBe(false);
			expect(result.refusal).toContain('substrate stays inert');
		}
		// The acquire path refuses at the consent gate (flag not admitted),
		// again before any transport call.
		const acquire = (await h.meet_local_lease_acquire({
			meetingId: 5,
			surfaces: ['microphone'],
		})) as { ok: false; refusal: string };
		expect(acquire.ok).toBe(false);
		expect(acquire.refusal).toContain('flag_not_admitted');
		expect(transport.postMeet).not.toHaveBeenCalled();
	});
});

describe('meet local capture composition — the execute-mode wire', () => {
	function executeHandlers(transport: MeetServerTransport, native = fakeNative()) {
		// identity() is the one probe the acquire path calls (the version-
		// pinned producer identity); the others stay loud — the wire never
		// runs a capture probe here.
		const preflightDeps: PreflightDeps = {
			...loudPreflightDeps(),
			identity: () => ({
				platform: 'darwin',
				platformVersion: '24.0.0',
				captureApiVersion: 'electron-test+chromium-test',
			}),
		};
		return {
			h: makeMeetLocalCaptureHandlers({
				native,
				transport,
				mode: 'execute',
				preflightDeps,
				nowMs: () => 1234,
			}),
			native,
		};
	}

	it('grant → verdict allowed → acquire carries the consented frames to the transport', async () => {
		const postMeet = vi.fn(async () => ({ recordingId: 9, leaseGeneration: 1 }));
		const { h } = executeHandlers({ postMeet });
		await h.meet_local_consent_grant({ meetingId: 5, surfaces: ['microphone'] });
		const acquire = (await h.meet_local_lease_acquire({
			meetingId: 5,
			surfaces: ['microphone'],
		})) as { recordingId: number };
		expect(acquire.recordingId).toBe(9);
		expect(postMeet).toHaveBeenCalledTimes(1);
		const [meetingId, path, body] = postMeet.mock.calls[0] as unknown as [
			number,
			string,
			{ deviceId: string; surfaces: string[]; producer: { platform: string } },
		];
		expect(meetingId).toBe(5);
		expect(path).toBe('/local/lease');
		expect(body.surfaces).toEqual(['microphone']);
		expect(body.producer.platform).toBeDefined();
		expect(body.deviceId).toMatch(/[0-9a-f-]{36}/);
	});

	it('the non-dismissible consent gate stands BEFORE any server call', async () => {
		const postMeet = vi.fn(async () => ({}));
		const { h } = executeHandlers({ postMeet });
		const acquire = (await h.meet_local_lease_acquire({
			meetingId: 5,
			surfaces: ['microphone'],
		})) as { ok: false; refusal: string };
		expect(acquire.ok).toBe(false);
		// An unasked scope is an UNKNOWN scope to the verdict (inspection
		// never materializes consent state) — the non-dismissible bar.
		expect(acquire.refusal).toContain('unknown_meeting');
		expect(postMeet).not.toHaveBeenCalled();

		// A grant covering a DIFFERENT surface set does not authorize more.
		await h.meet_local_consent_grant({ meetingId: 5, surfaces: ['microphone'] });
		const wider = (await h.meet_local_lease_acquire({
			meetingId: 5,
			surfaces: ['microphone', 'systemAudio'],
		})) as { ok: false; refusal: string };
		expect(wider.ok).toBe(false);
		expect(wider.refusal).toContain('surfaces_not_covered');
		expect(postMeet).not.toHaveBeenCalled();
	});

	it('heartbeats pass the caller frame through to the recording-scoped path', async () => {
		const postMeet = vi.fn(async () => ({ stop: false }));
		const { h } = executeHandlers({ postMeet });
		await h.meet_local_heartbeat({
			meetingId: 5,
			recordingId: 9,
			leaseGeneration: 1,
			seq: 7,
			captureState: 'capturing',
			diskFreeBytes: 4242,
		});
		expect(postMeet).toHaveBeenCalledWith(5, '/local/9/heartbeat', {
			leaseGeneration: 1,
			seq: 7,
			captureState: 'capturing',
			diskFreeBytes: 4242,
		});
	});

	it('the device id mints ONCE and lives under the renderer-denied namespace', () => {
		const native = fakeNative();
		const first = meetCaptureDeviceId(native);
		const second = meetCaptureDeviceId(native);
		expect(first).toBe(second);
		expect(native.secureStoreSet).toHaveBeenLastCalledWith(MEET_LOCAL_CAPTURE_DEVICE_KEY, first);
		expect(MEET_LOCAL_CAPTURE_CONSENT_KEY).toBe('meet-capture:consent');
		expect(MEET_LOCAL_CAPTURE_DEVICE_KEY).toBe('meet-capture:device');
	});
});

describe('the fail-closed meet transport', () => {
	it('refuses with no admitted origin and with no session credential', async () => {
		const empty = makeFetchMeetTransport({ getOrigin: () => '', getAccessToken: async () => 'tok' });
		await expect(empty.postMeet(5, '/local/lease', {})).rejects.toThrow(/no admitted server origin/);
		const noAuth = makeFetchMeetTransport({ getOrigin: () => 'https://s.test', getAccessToken: async () => null });
		await expect(noAuth.postMeet(5, '/local/lease', {})).rejects.toThrow(/no session credential/);
	});

	it('speaks only to the admitted origin with the session cookie, and rejects problems', async () => {
		const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ok: 1 }), { status: 200 }));
		vi.stubGlobal('fetch', fetchMock);
		const t = makeFetchMeetTransport({
			getOrigin: () => 'https://s.test',
			getAccessToken: async () => 'tok',
		});
		await t.postMeet(5, '/local/9/heartbeat', { seq: 1 });
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe('https://s.test/api/meet/5/local/9/heartbeat');
		expect((init.headers as Record<string, string>).Cookie).toBe('access_token=tok');
		expect(init.method).toBe('POST');

		vi.stubGlobal(
			'fetch',
			vi.fn(async () => new Response('no', { status: 404 })),
		);
		await expect(t.postMeet(5, '/local/9/heartbeat', { seq: 2 })).rejects.toThrow(/refused/);
	});
});
