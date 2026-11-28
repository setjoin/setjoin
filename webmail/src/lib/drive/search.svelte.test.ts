import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DriveSearchStore } from './search.svelte';

const searchNodes = vi.fn();

vi.mock('./api', async () => {
	const actual = await vi.importActual<typeof import('./api')>('./api');
	return {
		...actual,
		searchNodes: (...a: unknown[]) => searchNodes(...a),
	};
});

describe('DriveSearchStore', () => {
	beforeEach(() => {
		searchNodes.mockReset();
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('debounces 300ms before firing', async () => {
		searchNodes.mockResolvedValue({ items: [{ id: 1, spaceId: 1, parentId: null, kind: 'file', name: 'report.docx', createdAt: '' }] });
		const store = new DriveSearchStore();
		store.query('report');
		expect(searchNodes).not.toHaveBeenCalled();
		await vi.advanceTimersByTimeAsync(300);
		expect(searchNodes).toHaveBeenCalledTimes(1);
		expect(store.results).toHaveLength(1);
	});

	it('never fires below the 2-char floor', async () => {
		const store = new DriveSearchStore();
		store.query('r');
		await vi.advanceTimersByTimeAsync(500);
		expect(searchNodes).not.toHaveBeenCalled();
		expect(store.results).toEqual([]);
	});

	it('rapid keystrokes only fire once, for the final query', async () => {
		searchNodes.mockResolvedValue({ items: [] });
		const store = new DriveSearchStore();
		store.query('re');
		await vi.advanceTimersByTimeAsync(100);
		store.query('rep');
		await vi.advanceTimersByTimeAsync(100);
		store.query('report');
		await vi.advanceTimersByTimeAsync(300);
		expect(searchNodes).toHaveBeenCalledTimes(1);
		expect(searchNodes).toHaveBeenCalledWith('report', expect.objectContaining({ spaceId: null }));
	});

	it('a stale in-flight response never overwrites a newer one (AbortController cancel)', async () => {
		let resolveFirst: (v: { items: unknown[] }) => void = () => {};
		const first = new Promise((resolve) => {
			resolveFirst = resolve;
		});
		searchNodes.mockImplementationOnce(() => first).mockResolvedValueOnce({ items: [{ id: 2, spaceId: 1, parentId: null, kind: 'file', name: 'second.docx', createdAt: '' }] });

		const store = new DriveSearchStore();
		store.query('first');
		await vi.advanceTimersByTimeAsync(300);
		store.query('firstX'); // clear() cancels the debounce timer for 'first' before it can re-fire
		store.query('second');
		await vi.advanceTimersByTimeAsync(300);
		expect(store.results).toEqual([{ id: 2, spaceId: 1, parentId: null, kind: 'file', name: 'second.docx', createdAt: '' }]);

		// The stale first call resolving late must not clobber the newer result.
		resolveFirst({ items: [{ id: 1, spaceId: 1, parentId: null, kind: 'file', name: 'stale.docx', createdAt: '' }] });
		await Promise.resolve();
		await Promise.resolve();
		expect(store.results).toEqual([{ id: 2, spaceId: 1, parentId: null, kind: 'file', name: 'second.docx', createdAt: '' }]);
	});

	it('clear() resets results/loading/error and cancels any pending debounce', async () => {
		searchNodes.mockResolvedValue({ items: [{ id: 1, spaceId: 1, parentId: null, kind: 'file', name: 'x', createdAt: '' }] });
		const store = new DriveSearchStore();
		store.query('report');
		store.clear();
		await vi.advanceTimersByTimeAsync(500);
		expect(searchNodes).not.toHaveBeenCalled();
		expect(store.results).toEqual([]);
		expect(store.loading).toBe(false);
		expect(store.error).toBe(null);
	});
});
