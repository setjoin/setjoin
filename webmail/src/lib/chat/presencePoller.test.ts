import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
	createPresencePoller,
	PRESENCE_POLL_BASE_MS,
	PRESENCE_POLL_JITTER_MS,
} from './presencePoller';

function mulberry32(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

describe('createPresencePoller (#389)', () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('backs off failed presence polls with full jitter capped at 60s', async () => {
		const rng = mulberry32(0x7011001);
		const expectedRng = mulberry32(0x7011001);
		const poll = vi.fn<() => Promise<void>>().mockRejectedValue(new Error('gateway down'));

		const poller = createPresencePoller(poll, { backoff: { random: rng } });
		await poller.triggerNow();
		expect(poll).toHaveBeenCalledTimes(1);

		for (let attempt = 0; attempt < 9; attempt++) {
			const ceiling = Math.min(60_000, 1000 * 2 ** attempt);
			const expectedDelay = Math.floor(expectedRng() * ceiling);
			expect(expectedDelay).toBeGreaterThanOrEqual(0);
			expect(expectedDelay).toBeLessThanOrEqual(ceiling);
			expect(expectedDelay).toBeLessThanOrEqual(60_000);

			const beforeCalls = poll.mock.calls.length;
			if (expectedDelay > 0) {
				await vi.advanceTimersByTimeAsync(expectedDelay - 1);
				expect(poll).toHaveBeenCalledTimes(beforeCalls);
				await vi.advanceTimersByTimeAsync(1);
			} else {
				await vi.advanceTimersByTimeAsync(0);
			}
			expect(poll).toHaveBeenCalledTimes(beforeCalls + 1);
		}

		poller.stop();
	});

	it('resets backoff only after remaining healthy past stableUptimeMs, not on flapping polls', async () => {
		let shouldFail = true;
		const poll = vi.fn<() => Promise<void>>(async () => {
			if (shouldFail) throw new Error('flapping');
		});

		const poller = createPresencePoller(poll, {
			baseIntervalMs: 60_000,
			jitterMs: 0,
			backoff: { baseDelayMs: 1000, maxDelayMs: 60_000, stableUptimeMs: 15_000, random: () => 1 },
		});

		// Fail 1 (attempt 0 → 1000ms)
		await poller.triggerNow();
		expect(poll).toHaveBeenCalledTimes(1);

		// Retry succeeds at +1000ms, but an immediate re-trigger fails 2s later (< 15s stability).
		shouldFail = false;
		await vi.advanceTimersByTimeAsync(1000);
		expect(poll).toHaveBeenCalledTimes(2);

		vi.advanceTimersByTime(2_000);
		shouldFail = true;
		await poller.triggerNow();
		expect(poll).toHaveBeenCalledTimes(3);

		// Because uptime was 2s (< 15s), backoff did NOT reset → retry delay is 2000ms (attempt 1).
		await vi.advanceTimersByTimeAsync(1999);
		expect(poll).toHaveBeenCalledTimes(3);
		shouldFail = false;
		await vi.advanceTimersByTimeAsync(1);
		expect(poll).toHaveBeenCalledTimes(4);

		// Next steady-state poll runs 60s later (>= 15s stability) and fails → resets to 1000ms.
		shouldFail = true;
		await vi.advanceTimersByTimeAsync(60_000);
		expect(poll).toHaveBeenCalledTimes(5);
		await vi.advanceTimersByTimeAsync(999);
		expect(poll).toHaveBeenCalledTimes(5);
		await vi.advanceTimersByTimeAsync(1);
		expect(poll).toHaveBeenCalledTimes(6);

		poller.stop();
	});

	it('obeys the >=60s steady-state ceiling and spreads 100 clients on mass failure and steady polling', async () => {
		const CLIENT_COUNT = 100;
		let failing = true;
		const retryOffsets: Array<number | undefined> = new Array(CLIENT_COUNT);
		const steadyOffsets: Array<number | undefined> = new Array(CLIENT_COUNT);
		const startAt = Date.now();

		const pollers = Array.from({ length: CLIENT_COUNT }, (_, i) => {
			let calls = 0;
			return createPresencePoller(
				async () => {
					calls += 1;
					if (failing) {
						throw new Error('503');
					}
					if (calls === 2) {
						retryOffsets[i] = Date.now() - startAt;
					} else if (calls === 3) {
						steadyOffsets[i] = Date.now() - startAt;
					}
				},
				{ backoff: { random: mulberry32(40_000 + i) } },
			);
		});

		// All 100 fail simultaneously at t = 0.
		await Promise.all(pollers.map((p) => p.triggerNow()));
		// Gateway recovers before retries fire.
		failing = false;
		await vi.advanceTimersByTimeAsync(1000);

		expect(retryOffsets.every((v): v is number => typeof v === 'number')).toBe(true);
		const retries = retryOffsets as number[];
		expect(Math.min(...retries)).toBeGreaterThanOrEqual(0);
		expect(Math.max(...retries)).toBeLessThanOrEqual(1000);
		expect(Math.max(...retries) - Math.min(...retries)).toBeGreaterThan(750);
		expect(new Set(retries).size).toBeGreaterThan(80);

		// Steady-state next polls must all be >= 60s after recovery and well-spread across [60s, 90s].
		await vi.advanceTimersByTimeAsync(PRESENCE_POLL_BASE_MS + PRESENCE_POLL_JITTER_MS);
		expect(steadyOffsets.every((v): v is number => typeof v === 'number')).toBe(true);
		const steady = steadyOffsets as number[];
		for (let i = 0; i < CLIENT_COUNT; i++) {
			const delta = steady[i] - retries[i];
			expect(delta).toBeGreaterThanOrEqual(PRESENCE_POLL_BASE_MS);
			expect(delta).toBeLessThanOrEqual(PRESENCE_POLL_BASE_MS + PRESENCE_POLL_JITTER_MS);
		}
		expect(Math.max(...steady) - Math.min(...steady)).toBeGreaterThan(20_000);

		for (const p of pollers) p.stop();
	});

	it('coalesces overlapping triggerNow() calls into one trailing rerun without concurrent polls', async () => {
		let active = 0;
		let maxConcurrent = 0;
		let resolveFirst!: () => void;
		const firstGate = new Promise<void>((resolve) => {
			resolveFirst = resolve;
		});

		const poll = vi.fn<() => Promise<void>>(async () => {
			active += 1;
			maxConcurrent = Math.max(maxConcurrent, active);
			if (poll.mock.calls.length === 1) {
				await firstGate;
			}
			active -= 1;
		});

		const poller = createPresencePoller(poll, { backoff: { random: () => 0.5 } });

		const first = poller.triggerNow();
		// Two overlapping retriggers while the first poll is still in flight.
		const overlapA = poller.triggerNow();
		const overlapB = poller.triggerNow();

		expect(poll).toHaveBeenCalledTimes(1);
		expect(maxConcurrent).toBe(1);

		resolveFirst();
		await Promise.all([first, overlapA, overlapB]);
		// Let the coalesced trailing rerun settle.
		await Promise.resolve();

		expect(poll).toHaveBeenCalledTimes(2);
		expect(maxConcurrent).toBe(1);

		poller.stop();
	});

	it('stop() cancels pending timers and prevents further polls', async () => {
		const poll = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
		const poller = createPresencePoller(poll, { backoff: { random: () => 0.5 } });
		await poller.triggerNow();
		expect(poll).toHaveBeenCalledTimes(1);

		poller.stop();
		await vi.advanceTimersByTimeAsync(300_000);
		expect(poll).toHaveBeenCalledTimes(1);
	});
});
