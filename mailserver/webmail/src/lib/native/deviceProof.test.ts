import { describe, it, expect, vi, afterEach } from 'vitest';
import { attachDeviceProofHeaders } from './deviceProof';

afterEach(() => {
	delete (window as unknown as { setjoinNative?: unknown }).setjoinNative;
});

describe('attachDeviceProofHeaders', () => {
	it('attaches X-Device-* when the bridge advertises deviceProof', async () => {
		(window as unknown as { setjoinNative: unknown }).setjoinNative = {
			version: 1,
			capabilities: ['deviceProof'],
			deviceProof: vi.fn(async () => ({ hmac: 'abc123' })),
			secureStore: { get: async () => 'dev-7' }
		};
		const h = new Headers();
		await attachDeviceProofHeaders(h);
		expect(h.get('X-Device-HMAC')).toBe('abc123');
		expect(h.get('X-Device-ID')).toBe('dev-7');
		expect(h.has('X-Device-Timestamp')).toBe(true);
	});

	it('attaches nothing in a plain browser (no bridge)', async () => {
		const h = new Headers();
		await attachDeviceProofHeaders(h);
		expect(h.has('X-Device-HMAC')).toBe(false);
	});

	it('swallows vault errors and attaches no headers (vault corruption resilience)', async () => {
		(window as unknown as { setjoinNative: unknown }).setjoinNative = {
			version: 1,
			capabilities: ['deviceProof'],
			deviceProof: vi.fn(async () => { throw new Error('i64 parse error: invalid device_id'); }),
			secureStore: { get: async () => 'bad-id' }
		};
		const h = new Headers();
		await expect(attachDeviceProofHeaders(h)).resolves.toBeUndefined();
		expect(h.has('X-Device-HMAC')).toBe(false);
	});
});
