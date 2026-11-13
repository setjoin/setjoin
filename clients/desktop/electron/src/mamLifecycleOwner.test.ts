import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import {
	DEFAULT_MAM_ROLLOUT_MODE,
	MAM_PERIODIC_INTERVAL_MS,
	MamLifecycleOwner,
	type MamLifecycleClock,
} from './mamLifecycleOwner';

const corpus = JSON.parse(
	readFileSync(new URL('../../../mam/conformance/v1/lifecycle.json', import.meta.url), 'utf8'),
) as { default_rollout_mode: string; periodic_interval_ms: number; rollout_modes: string[] };

function fakeClock() {
	let callback: (() => void) | null = null;
	const clearInterval = vi.fn();
	const clock: MamLifecycleClock = {
		setInterval: vi.fn((cb) => {
			callback = cb;
			return 7 as unknown as ReturnType<typeof setInterval>;
		}),
		clearInterval,
	};
	return { clock, tick: () => callback?.(), clearInterval };
}

async function flush(): Promise<void> {
	for (let i = 0; i < 8; i += 1) await Promise.resolve();
}

describe('MamLifecycleOwner', () => {
	it('pins the shared off/observe/execute default-OFF contract', () => {
		expect(corpus.rollout_modes).toEqual(['off', 'observe', 'execute']);
		expect(DEFAULT_MAM_ROLLOUT_MODE).toBe(corpus.default_rollout_mode);
		expect(MAM_PERIODIC_INTERVAL_MS).toBe(corpus.periodic_interval_ms);
	});

	it('starts once, coalesces re-entry, resumes once, and stops its only timer', async () => {
		const { clock, tick, clearInterval } = fakeClock();
		const checkin = vi.fn(async () => {});
		const owner = new MamLifecycleOwner('execute', checkin, () => {}, clock);

		owner.start();
		owner.start();
		await flush();
		expect(checkin).toHaveBeenCalledTimes(1);
		expect(clock.setInterval).toHaveBeenCalledTimes(1);

		owner.pause();
		owner.resume();
		owner.resume();
		await flush();
		expect(checkin).toHaveBeenCalledTimes(2);

		tick();
		await flush();
		expect(checkin).toHaveBeenCalledTimes(3);
		owner.stop();
		owner.stop();
		expect(clearInterval).toHaveBeenCalledTimes(1);
		tick();
		await flush();
		expect(checkin).toHaveBeenCalledTimes(3);
	});

	it('keeps off and observe modes inert', async () => {
		for (const mode of ['off', 'observe'] as const) {
			const { clock } = fakeClock();
			const checkin = vi.fn(async () => {});
			const owner = new MamLifecycleOwner(mode, checkin, () => {}, clock);
			owner.start();
			owner.pause();
			owner.resume();
			await flush();
			expect(checkin, mode).not.toHaveBeenCalled();
			expect(clock.setInterval, mode).not.toHaveBeenCalled();
		}
	});

	it('queues at most one opportunity while a check-in is in flight', async () => {
		const { clock, tick } = fakeClock();
		let release: (() => void) | undefined;
		const checkin = vi.fn(() => new Promise<void>((resolve) => { release = resolve; }));
		const owner = new MamLifecycleOwner('execute', checkin, () => {}, clock);
		owner.start();
		await flush();
		tick();
		tick();
		expect(checkin).toHaveBeenCalledTimes(1);
		release?.();
		await flush();
		expect(checkin).toHaveBeenCalledTimes(2);
		owner.stop();
	});
});
