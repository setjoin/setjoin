import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DriveWatchStore, driveWatches } from './watches.svelte';
import type { DriveWatchRow } from './api';

const listWatches = vi.fn();
const setWatch = vi.fn();
const removeWatch = vi.fn();

vi.mock('./api', async () => {
	const actual = await vi.importActual<typeof import('./api')>('./api');
	return {
		...actual,
		listWatches: (...a: unknown[]) => listWatches(...a),
		setWatch: (...a: unknown[]) => setWatch(...a),
		removeWatch: (...a: unknown[]) => removeWatch(...a),
	};
});

const ROW: DriveWatchRow = { nodeId: 42, nodeName: 'Report.xlsx', kind: 'file', ops: null };

describe('DriveWatchStore', () => {
	beforeEach(() => {
		listWatches.mockReset();
		setWatch.mockReset();
		removeWatch.mockReset();
	});

	it('load() populates list()/isWatched() from the server', async () => {
		listWatches.mockResolvedValue([ROW]);
		const store = new DriveWatchStore();
		expect(store.isWatched(42)).toBe(false);

		await store.load();

		expect(store.list()).toEqual([ROW]);
		expect(store.isWatched(42)).toBe(true);
		expect(store.isWatched(999)).toBe(false);
	});

	it('toggle() adds a watch (setWatch) when unwatched, then refreshes', async () => {
		listWatches.mockResolvedValueOnce([]).mockResolvedValueOnce([ROW]);
		setWatch.mockResolvedValue(undefined);
		const store = new DriveWatchStore();
		await store.load();
		expect(store.isWatched(42)).toBe(false);

		await store.toggle(42);

		expect(setWatch).toHaveBeenCalledWith(42, undefined);
		expect(removeWatch).not.toHaveBeenCalled();
		expect(store.isWatched(42)).toBe(true);
	});

	it('toggle() removes a watch (removeWatch) when already watched, then refreshes', async () => {
		listWatches.mockResolvedValueOnce([ROW]).mockResolvedValueOnce([]);
		removeWatch.mockResolvedValue(undefined);
		const store = new DriveWatchStore();
		await store.load();
		expect(store.isWatched(42)).toBe(true);

		await store.toggle(42);

		expect(removeWatch).toHaveBeenCalledWith(42);
		expect(setWatch).not.toHaveBeenCalled();
		expect(store.isWatched(42)).toBe(false);
	});

	// The behavior-fix test: before this store existed, DriveApp, VersionDrawer,
	// and SubscriptionsSheet each held a PRIVATE listWatches() cache, so a
	// toggle in one never reached the others. Simulate two independent
	// "components" reading off the SAME store instance and assert a mutation
	// from one is immediately visible to the other, with no refetch of its own.
	it('a toggle from one reader propagates to a second independent reader (cross-observer)', async () => {
		listWatches.mockResolvedValueOnce([]).mockResolvedValueOnce([ROW]);
		setWatch.mockResolvedValue(undefined);
		const store = new DriveWatchStore();
		await store.load();

		// "Component A" — e.g. the VersionDrawer bell button.
		const readerA = () => store.isWatched(42);
		// "Component B" — e.g. the SubscriptionsSheet list, never itself calling load() again.
		const readerB = () => store.list().some((w) => w.nodeId === 42);

		expect(readerA()).toBe(false);
		expect(readerB()).toBe(false);

		await store.toggle(42); // the mutation happens via "component A"

		expect(readerA()).toBe(true);
		expect(readerB()).toBe(true); // "component B" sees it without any action of its own
	});

	it('watch() is unconditional add (does not flip an already-watched node)', async () => {
		listWatches.mockResolvedValueOnce([ROW]).mockResolvedValueOnce([ROW]);
		setWatch.mockResolvedValue(undefined);
		const store = new DriveWatchStore();
		await store.load();

		await store.watch(42, ['create', 'update']);

		expect(setWatch).toHaveBeenCalledWith(42, ['create', 'update']);
		expect(store.isWatched(42)).toBe(true);
	});

	it('unwatch() is unconditional remove', async () => {
		listWatches.mockResolvedValueOnce([ROW]).mockResolvedValueOnce([]);
		removeWatch.mockResolvedValue(undefined);
		const store = new DriveWatchStore();
		await store.load();

		await store.unwatch(42);

		expect(removeWatch).toHaveBeenCalledWith(42);
		expect(store.isWatched(42)).toBe(false);
	});

	it('exports a shared singleton instance', () => {
		expect(driveWatches).toBeInstanceOf(DriveWatchStore);
	});
});
