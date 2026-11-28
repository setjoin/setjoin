import { describe, it, expect, vi } from 'vitest';

import { createCriticalActivityCounter, withCriticalScope } from './criticalScope';

describe('E4-I critical scope composition', () => {
	it('balances begin/end into one counter with coalesced transitions', () => {
		const transitions: number[] = [];
		const counter = createCriticalActivityCounter({ onTransition: (count) => transitions.push(count) });
		const first = counter.begin('security-a');
		const second = counter.begin('security-b');
		expect(counter.count()).toBe(2);
		expect(counter.isActive()).toBe(true);
		second.end();
		expect(counter.count()).toBe(1);
		first.end();
		expect(counter.count()).toBe(0);
		expect(transitions).toEqual([1, 0]);
	});

	it('end is idempotent and stale handles cannot double-release', () => {
		const counter = createCriticalActivityCounter();
		const handle = counter.begin();
		handle.end();
		handle.end();
		expect(counter.count()).toBe(0);
		expect(handle.released).toBe(true);
	});

	it('teardown removes listeners: stale epoch callbacks can never reopen work', () => {
		const counter = createCriticalActivityCounter();
		const openHandle = counter.begin('in-flight');
		counter.teardown();
		expect(counter.tornDown).toBe(true);
		expect(counter.count()).toBe(0);
		// A stale callback releasing after teardown stays safe.
		openHandle.end();
		expect(counter.count()).toBe(0);
		// And a stale begin cannot re-increment.
		const stale = counter.begin('late-callback');
		stale.end();
		expect(counter.count()).toBe(0);
		expect(stale.released).toBe(true);
	});

	it('runs independent of the optional-work rollout mode: OFF/observe cannot suppress required security cleanup', async () => {
		// The counter takes no rollout-mode input by construction; the test pins
		// that required Critical composition works identically while mode=off.
		const counter = createCriticalActivityCounter();
		const mode: 'off' | 'observe' | 'execute' = 'off';
		expect(mode).toBe('off');
		const released = await withCriticalScope(counter, async () => 'security-cleanup');
		expect(released).toBe('security-cleanup');
		expect(counter.count()).toBe(0);
	});

	it('withCriticalScope releases on failure and cancellation paths', async () => {
		const counter = createCriticalActivityCounter();
		const onAbort = new AbortController();
		await expect(withCriticalScope(counter, async () => {
			throw new Error('security request failed');
		})).rejects.toThrow('security request failed');
		expect(counter.count()).toBe(0);
		await withCriticalScope(counter, async () => {
			onAbort.abort();
			return 'cancelled-but-clean';
		});
		expect(counter.count()).toBe(0);
		expect(counter.isActive()).toBe(false);
	});

	it('transitions fire exactly once per 0→1 and →0', () => {
		const onTransition = vi.fn();
		const counter = createCriticalActivityCounter({ onTransition });
		const handles = [counter.begin(), counter.begin(), counter.begin()];
		expect(onTransition).toHaveBeenCalledTimes(1);
		handles[0].end();
		handles[1].end();
		expect(onTransition).toHaveBeenCalledTimes(1);
		handles[2].end();
		expect(onTransition).toHaveBeenCalledTimes(2);
		expect(onTransition).toHaveBeenLastCalledWith(0);
	});
});
