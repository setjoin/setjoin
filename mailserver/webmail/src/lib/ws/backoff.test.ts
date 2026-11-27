import { describe, expect, it } from 'vitest';
import {
	computeBackoffCeilingMs,
	computeFullJitterDelayMs,
	computeJitteredIntervalMs,
	DEFAULT_BASE_DELAY_MS,
	DEFAULT_MAX_DELAY_MS,
	DEFAULT_STABLE_UPTIME_MS,
	ReconnectBackoff,
} from './backoff';

/** Deterministic PRNG (Mulberry32) in [0, 1) for reproducible backoff tests. */
function mulberry32(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

describe('backoff helpers (#389)', () => {
	it('computes exponential ceilings from 1s and caps at 60s without overflow', () => {
		expect(computeBackoffCeilingMs(0)).toBe(1000);
		expect(computeBackoffCeilingMs(1)).toBe(2000);
		expect(computeBackoffCeilingMs(2)).toBe(4000);
		expect(computeBackoffCeilingMs(3)).toBe(8000);
		expect(computeBackoffCeilingMs(4)).toBe(16000);
		expect(computeBackoffCeilingMs(5)).toBe(32000);
		expect(computeBackoffCeilingMs(6)).toBe(60000);
		expect(computeBackoffCeilingMs(7)).toBe(60000);
		expect(computeBackoffCeilingMs(100)).toBe(60000);
		expect(computeBackoffCeilingMs(-3)).toBe(1000);
	});

	it('produces deterministic full-jitter delays strictly inside [0, min(cap, base * 2^attempt)]', () => {
		const rng = mulberry32(0x3890001);
		for (let attempt = 0; attempt < 25; attempt++) {
			const ceiling = Math.min(DEFAULT_MAX_DELAY_MS, DEFAULT_BASE_DELAY_MS * 2 ** Math.min(attempt, 30));
			const delay = computeFullJitterDelayMs(attempt, DEFAULT_BASE_DELAY_MS, DEFAULT_MAX_DELAY_MS, rng);
			expect(Number.isInteger(delay)).toBe(true);
			expect(delay).toBeGreaterThanOrEqual(0);
			expect(delay).toBeLessThanOrEqual(ceiling);
			expect(delay).toBeLessThanOrEqual(DEFAULT_MAX_DELAY_MS);
		}
	});

	it('clamps boundary and non-finite RNG outputs safely', () => {
		expect(computeFullJitterDelayMs(0, 1000, 60_000, () => 0)).toBe(0);
		expect(computeFullJitterDelayMs(0, 1000, 60_000, () => -1)).toBe(0);
		expect(computeFullJitterDelayMs(0, 1000, 60_000, () => 0.5)).toBe(500);
		expect(computeFullJitterDelayMs(0, 1000, 60_000, () => 0.9999)).toBe(999);
		expect(computeFullJitterDelayMs(0, 1000, 60_000, () => 1)).toBe(1000);
		expect(computeFullJitterDelayMs(0, 1000, 60_000, () => 5)).toBe(1000);
		expect(computeFullJitterDelayMs(0, 1000, 60_000, () => Number.NaN)).toBe(500);
	});

	it('computeJitteredIntervalMs stays within [base, base + jitter]', () => {
		const rng = mulberry32(42);
		for (let i = 0; i < 50; i++) {
			const interval = computeJitteredIntervalMs(60_000, 30_000, rng);
			expect(interval).toBeGreaterThanOrEqual(60_000);
			expect(interval).toBeLessThanOrEqual(90_000);
		}
		expect(computeJitteredIntervalMs(60_000, 0, rng)).toBe(60_000);
	});
});

describe('ReconnectBackoff stability-gated resets (#389)', () => {
	it('does not reset on flapping connections that drop before stableUptimeMs', () => {
		let now = 1_000_000;
		const backoff = new ReconnectBackoff({
			baseDelayMs: 1000,
			maxDelayMs: 60_000,
			stableUptimeMs: DEFAULT_STABLE_UPTIME_MS,
			// Fixed 1.0 returns exact ceilings so attempt progression is directly observable.
			random: () => 1,
			now: () => now,
		});

		const expectedCeilings = [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000];
		for (const expected of expectedCeilings) {
			backoff.markConnected();
			// Stay connected just under the 15s stability threshold, then drop.
			now += DEFAULT_STABLE_UPTIME_MS - 1;
			expect(backoff.hasReachedStableUptime()).toBe(false);
			expect(backoff.markDisconnected()).toBe(expected);
		}
	});

	it('resets attempt back to 0 only after staying connected >= stableUptimeMs', () => {
		let now = 500_000;
		const backoff = new ReconnectBackoff({
			baseDelayMs: 1000,
			maxDelayMs: 60_000,
			stableUptimeMs: 15_000,
			random: () => 1,
			now: () => now,
		});

		// Three failed attempts without ever connecting → attempt reaches 3.
		expect(backoff.markDisconnected()).toBe(1000);
		expect(backoff.markDisconnected()).toBe(2000);
		expect(backoff.markDisconnected()).toBe(4000);
		expect(backoff.attempt).toBe(3);

		// Connect, flap after 5s → still NOT reset, uses attempt 3 (8000).
		backoff.markConnected();
		now += 5_000;
		expect(backoff.markDisconnected()).toBe(8000);
		expect(backoff.attempt).toBe(4);

		// Connect, stay healthy for 15s (redundant markConnected mid-way must not restart clock).
		backoff.markConnected();
		now += 10_000;
		backoff.markConnected();
		now += 5_000;
		expect(backoff.hasReachedStableUptime()).toBe(true);

		// Next drop resets to attempt 0 → ceiling 1000.
		expect(backoff.markDisconnected()).toBe(1000);
		expect(backoff.attempt).toBe(1);
	});

	it('spreads 100 simultaneous mass-disconnect clients across the backoff window', () => {
		const clients = Array.from({ length: 100 }, (_, i) =>
			new ReconnectBackoff({
				baseDelayMs: 1000,
				maxDelayMs: 60_000,
				random: mulberry32(10_000 + i),
				now: () => 0,
			}),
		);

		const delays = clients.map((c) => c.markDisconnected());
		const unique = new Set(delays);
		const min = Math.min(...delays);
		const max = Math.max(...delays);

		// 100 clients over [0, 1000) should span most of the window with high uniqueness.
		expect(min).toBeGreaterThanOrEqual(0);
		expect(max).toBeLessThanOrEqual(1000);
		expect(max - min).toBeGreaterThan(750);
		expect(unique.size).toBeGreaterThan(80);
	});
});
