import { beforeEach, describe, expect, it, vi } from 'vitest';

import { markProductInteractive, markProductReady } from './marks';

describe('product performance marks', () => {
	beforeEach(() => {
		performance.clearMarks();
	});

	it('records each product state at most once', () => {
		markProductReady('public-visible');
		markProductReady('public-visible');
		expect(performance.getEntriesByName('public-visible', 'mark')).toHaveLength(1);
	});

	it('records interactive readiness on the next animation frame', () => {
		const callbacks: FrameRequestCallback[] = [];
		vi.spyOn(globalThis, 'requestAnimationFrame').mockImplementation((callback) => {
			callbacks.push(callback);
			return callbacks.length;
		});
		vi.spyOn(globalThis, 'cancelAnimationFrame').mockImplementation(() => {});

		markProductInteractive('inbox-interactive');
		expect(performance.getEntriesByName('inbox-interactive', 'mark')).toHaveLength(0);
		callbacks[0](performance.now());
		expect(performance.getEntriesByName('inbox-interactive', 'mark')).toHaveLength(1);
	});
});
