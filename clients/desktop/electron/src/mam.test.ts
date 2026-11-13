import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { deviceHmac, policyFromMap, makeMamHandlers } from './mam';
import { buildCheckinRequest, reduceCheckinResponse } from './mamLifecycle';
import type { NativeBinding } from './native';

interface MamCorpus {
	version: number;
	signing_vectors: Array<{
		name: string;
		secret: string;
		device_id: number;
		timestamp: string;
		challenge: string;
		hmac_sha256_hex: string;
	}>;
	request_vectors: Array<{
		name: string;
		server_url: string;
		device_id: number;
		known_policy_version: number;
		timestamp: string;
		secret: string;
		expected_url: string;
		expected_headers: Record<string, string>;
		expected_body: Record<string, number>;
	}>;
	response_vectors: Array<{
		name: string;
		status: number;
		known_policy_version: number;
		body: {
			policy_version: number;
			policy?: Record<string, string>;
			wipe_requested: boolean;
		} | null;
		expected: {
			policy_version: number;
			wiped: boolean;
			normalized_policy?: Record<string, string | number | boolean>;
			effect_intents: string[];
			forbidden_effect_intents?: string[];
		};
	}>;
}

const corpus = JSON.parse(
	readFileSync(new URL('../../../mam/conformance/v1/lifecycle.json', import.meta.url), 'utf8'),
) as MamCorpus;

function fakeNative(over: Partial<NativeBinding> = {}): NativeBinding {
	const store: Record<string, string> = {};
	return {
		vaultUnlock: () => true,
		vaultIsUnlocked: () => true,
		vaultListTotp: () => [],
		vaultGenerateTotp: () => '000000',
		secureStoreGet: (k) => (k in store ? store[k] : null),
		secureStoreSet: (k, v) => {
			store[k] = v;
		},
		secureStoreRemove: (k) => {
			delete store[k];
		},
		dbOpen: () => {},
		dbIsOpen: () => false,
		dbExec: () => 0,
		dbExecSchemaInit: () => 0,
		dbTransactionBatch: () => 0,
		dbMigrateStore: () => '{"version":2}',
		dbQuery: () => '[]',
		dbWipe: () => {},
		driveImportFile: async () => '{"contentSha256":"","size":0,"chunks":[]}',
		driveFetchChunk: async () => {},
		drivePushChunk: async () => 200,
		driveHasChunk: () => false,
		driveDeleteChunks: () => 0,
		driveSetConfinement: () => {},
		driveServeStart: async () => '{"port":0}',
		driveServeGrant: () => '/t/fake',
		driveServeRevoke: () => {},
		driveServeStop: () => {},
		mamStoreDeviceId: vi.fn(),
		mamStorePolicy: vi.fn(),
		mamGetPolicy: () => null,
		mamMarkWiped: vi.fn(),
		mamIsWiped: () => false,
		mamClearWiped: vi.fn(),
		...over,
	};
}

describe('device_hmac (golden — pins the authserver wire contract)', () => {
	it('matches every versioned cross-shell signing vector', () => {
		expect(corpus.version).toBe(1);
		for (const vector of corpus.signing_vectors) {
			expect(`${vector.device_id}:${vector.timestamp}`, vector.name).toBe(vector.challenge);
			const got = deviceHmac(vector.secret, vector.device_id, vector.timestamp);
			expect(got, vector.name).toBe(vector.hmac_sha256_hex);
			expect(/^[0-9a-f]{64}$/.test(got), vector.name).toBe(true);
		}
	});
});

describe('policy_from_map (ported)', () => {
	it('maps known keys with the right coercions', () => {
		const vector = corpus.response_vectors.find((v) => v.name === 'changed-policy-normalizes-flat-map')!;
		const p = policyFromMap(vector.body!.policy_version, vector.body!.policy!);
		expect(p).toEqual(vector.expected.normalized_policy);
	});

	it('defaults absent keys to the permissive baseline', () => {
		const vector = corpus.response_vectors.find((v) => v.name === 'empty-policy-uses-permissive-defaults')!;
		const p = policyFromMap(vector.body!.policy_version, vector.body!.policy!);
		expect(p).toEqual(vector.expected.normalized_policy);
	});
});

describe('pure MAM lifecycle transition module', () => {
	it('builds every corpus request without native or network effects', () => {
		for (const vector of corpus.request_vectors) {
			const request = buildCheckinRequest(
				vector.server_url,
				vector.device_id,
				vector.secret,
				vector.timestamp,
				vector.known_policy_version,
			);
			expect(request.url, vector.name).toBe(vector.expected_url);
			expect(request.headers, vector.name).toEqual(vector.expected_headers);
			expect(request.body, vector.name).toEqual(vector.expected_body);
		}
	});

	it('reduces every corpus response to the same ordered effect intents', () => {
		for (const vector of corpus.response_vectors) {
			const transition = reduceCheckinResponse(
				vector.status,
				vector.known_policy_version,
				42,
				vector.body,
			);
			expect(transition.outcome, vector.name).toEqual({
				ran: true,
				policy_version: vector.expected.policy_version,
				wiped: vector.expected.wiped,
			});
			expect(
				transition.effects.map((effect) => effect.type),
				vector.name,
			).toEqual(vector.expected.effect_intents);
			const cachedPolicy = transition.effects.find((effect) => effect.type === 'cache_policy');
			if (cachedPolicy?.type === 'cache_policy') {
				expect(cachedPolicy.policy, vector.name).toEqual(vector.expected.normalized_policy);
			}
		}
	});

	it('fails closed on error statuses or a missing successful response', () => {
		expect(() => reduceCheckinResponse(503, 4, 42, null)).toThrow('server returned 503');
		expect(() => reduceCheckinResponse(200, 4, 42, null)).toThrow('bad response');
	});
});

describe('mam handlers', () => {
	it('mam_enroll writes the mam:* keys, clears wipe, caches device id', () => {
		const native = fakeNative();
		const h = makeMamHandlers(native, { clearStorage: async () => {} });
		h.mam_enroll('https://mdm.example/', 42, 's3cr3t');
		expect(native.secureStoreGet('mam:server_url')).toBe('https://mdm.example/');
		expect(native.secureStoreGet('mam:device_id')).toBe('42');
		expect(native.secureStoreGet('mam:hmac_secret')).toBe('s3cr3t');
		expect(native.mamClearWiped).toHaveBeenCalled();
		expect(native.mamStoreDeviceId).toHaveBeenCalledWith('42');
	});

	it('mam_enroll rejects renderer-supplied triples that fail endpoint validation (D-CLIENTS-DESKTOP-006)', () => {
		const native = fakeNative();
		const h = makeMamHandlers(native, { clearStorage: async () => {} });
		// scheme downgrade / non-https / unparseable / credentialed / host-less
		for (const bad of [
			'http://mdm.example/',
			'ftp://mdm.example/',
			'not-a-url',
			'https://user:pass@mdm.example/',
			'',
			'https://',
		]) {
			expect(() => h.mam_enroll(bad, 42, 's3cr3t'), bad).toThrow(/mam_enroll:/);
		}
		// invalid device ids and empty secret
		expect(() => h.mam_enroll('https://mdm.example/', '42abc', 's')).toThrow(/device_id/);
		expect(() => h.mam_enroll('https://mdm.example/', -1, 's')).toThrow(/device_id/);
		expect(() => h.mam_enroll('https://mdm.example/', 42, '')).toThrow(/hmac_secret/);
		// fail-closed: no store writes, no wipe-latch clear, no device-id cache
		expect(native.secureStoreGet('mam:server_url')).toBeNull();
		expect(native.secureStoreGet('mam:device_id')).toBeNull();
		expect(native.secureStoreGet('mam:hmac_secret')).toBeNull();
		expect(native.mamClearWiped).not.toHaveBeenCalled();
		expect(native.mamStoreDeviceId).not.toHaveBeenCalled();
	});

	it('device_proof returns {hmac} when enrolled, null when not', () => {
		const native = fakeNative();
		const h = makeMamHandlers(native, { clearStorage: async () => {} });
		// not enrolled → null
		expect(h.device_proof('42', '1700000000')).toBeNull();
		// enroll then proof matches the golden
		h.mam_enroll('https://x', 42, 'secret');
		const proof = h.device_proof('42', '1700000000') as { hmac: string };
		expect(proof.hmac).toBe(deviceHmac('secret', 42, '1700000000'));
	});

	it('device_proof rejects a non-numeric device id', () => {
		const native = fakeNative();
		native.secureStoreSet('mam:hmac_secret', 'secret');
		const h = makeMamHandlers(native, { clearStorage: async () => {} });
		expect(() => h.device_proof('not-a-number', '1')).toThrow(/invalid device_id/);
	});

	it('mam_checkin no-ops when not enrolled, latches wipe on wipe_requested', async () => {
		const native = fakeNative();
		const clearStorage = vi.fn(async () => {});
		const h = makeMamHandlers(native, {
			clearStorage,
			fetch: (async () =>
				new Response(JSON.stringify({ policy_version: 5, wipe_requested: true }), {
					status: 200,
				})) as typeof fetch,
		});
		// not enrolled → ran:false
		expect(await h.mam_checkin()).toEqual({ ran: false, policy_version: 0, wiped: false });
		// enrolled + server asks wipe → latched
		h.mam_enroll('https://x', 42, 'secret');
		const out = (await h.mam_checkin()) as { ran: boolean; wiped: boolean };
		expect(out.wiped).toBe(true);
		expect(native.mamMarkWiped).toHaveBeenCalled();
		expect(clearStorage).toHaveBeenCalled();
	});

	it('builds the signed request and preserves cached policy on the corpus 304 vector', async () => {
		const vector = corpus.request_vectors.find((v) => v.name === 'signed-checkin-with-cached-version')!;
		const native = fakeNative({
			mamGetPolicy: () => JSON.stringify({ policy_version: vector.known_policy_version }),
		});
		let capturedUrl = '';
		let capturedInit: RequestInit | undefined;
		const now = vi.spyOn(Date, 'now').mockReturnValue(Number(vector.timestamp) * 1000);
		try {
			const h = makeMamHandlers(native, {
				clearStorage: async () => {},
				fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
					capturedUrl = String(input);
					capturedInit = init;
					return new Response(null, { status: 304 });
				}) as typeof fetch,
			});
			h.mam_enroll(vector.server_url, vector.device_id, vector.secret);
			const out = await h.mam_checkin();

			expect(capturedUrl).toBe(vector.expected_url);
			expect(capturedInit?.headers).toEqual(vector.expected_headers);
			expect(JSON.parse(String(capturedInit?.body))).toEqual(vector.expected_body);
			expect(out).toEqual({ ran: true, policy_version: vector.known_policy_version, wiped: false });
			expect(native.mamStorePolicy).not.toHaveBeenCalled();
		} finally {
			now.mockRestore();
		}
	});

	it('normalizes the corpus policy response before caching it', async () => {
		const vector = corpus.response_vectors.find((v) => v.name === 'changed-policy-normalizes-flat-map')!;
		const native = fakeNative();
		const h = makeMamHandlers(native, {
			clearStorage: async () => {},
			fetch: (async () => new Response(JSON.stringify(vector.body), { status: vector.status })) as typeof fetch,
		});
		h.mam_enroll('https://x', 42, 'test-only-secret');
		const out = await h.mam_checkin();

		expect(out).toEqual({ ran: true, policy_version: vector.expected.policy_version, wiped: false });
		expect(native.mamStorePolicy).toHaveBeenCalledWith(JSON.stringify(vector.expected.normalized_policy));
	});

	it('executes the corpus wipe intents in order and never caches the accompanying policy', async () => {
		const vector = corpus.response_vectors.find((v) => v.name === 'wipe-precedes-policy')!;
		const effects: string[] = [];
		const native = fakeNative({
			mamStoreDeviceId: vi.fn(() => effects.push('cache_device')),
			mamStorePolicy: vi.fn(() => effects.push('cache_policy')),
			mamMarkWiped: vi.fn(() => effects.push('latch_wipe')),
		});
		const h = makeMamHandlers(native, {
			clearStorage: async () => {
				effects.push('clear_web_storage');
			},
			fetch: (async () => new Response(JSON.stringify(vector.body), { status: vector.status })) as typeof fetch,
		});
		h.mam_enroll('https://x', 42, 'test-only-secret');
		effects.length = 0;
		const out = await h.mam_checkin();

		expect(out).toEqual({ ran: true, policy_version: vector.expected.policy_version, wiped: true });
		expect(effects).toEqual(vector.expected.effect_intents);
		for (const forbidden of vector.expected.forbidden_effect_intents ?? []) {
			expect(effects).not.toContain(forbidden);
		}
	});
});
