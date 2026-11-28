/**
 * Bounded-step edge branches (coverage round r2).
 *
 * Real behavior tests for the delta/window step edges the main suites leave
 * cold: corrupt/foreign cursor decoding falls back to a fresh anchor, a
 * non-cannotCalculateChanges changes failure propagates, a plain-string
 * cannotCalculateChanges still maps to blocked, the outbox-pending skip in
 * the delta loop, destroyed-id budget/abort stops with their page-cursor
 * remainder, the default clock's non-performance fallback, and the window
 * step's abort/expiry early returns, empty-page completion, post-query abort
 * and mid-page loop stops.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

import type { Email } from '$lib/types/jmap';
import type { SyncCheckpoint } from './work-contract';
import { createSyncDeltaStep, createSyncWindowStep, defaultStepClock } from './steps';
import { createMemoryOfflineStore } from '$lib/native/testing/backgroundWorkHarness';

function email(id: string, receivedAtIso: string): Email {
	return {
		id,
		threadId: 't',
		mailboxIds: { Inbox: true },
		keywords: { $seen: true },
		receivedAt: receivedAtIso,
		hasAttachment: false,
		preview: 'p',
		subject: 's',
	} as unknown as Email;
}

const BUDGET = { maxRecords: 64 as const, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: Number.MAX_SAFE_INTEGER };

function options(
	store: ReturnType<typeof createMemoryOfflineStore>,
	checkpoint: SyncCheckpoint | null = null,
	signal = new AbortController().signal,
	budget = BUDGET,
) {
	return { store, accountId: 'acct-1', signal, budget, checkpoint };
}

const FRESH_BUDGET = { maxRecords: 64 as const, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 };

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('delta step cursor decoding', () => {
	it('a page cursor with a malformed payload falls back to a fresh anchor (no throw)', async () => {
		const store = createMemoryOfflineStore();
		let anchorGets = 0;
		let changesCalls = 0;
		const client = {
			emailChanges: async () => {
				changesCalls += 1;
				return { newState: '43', hasMoreChanges: false, created: [], updated: [], destroyed: [] };
			},
			emailGet: async ({ ids }: { ids: string[] }) => {
				if (ids.length === 0) anchorGets += 1;
				return { list: [], state: '42' };
			},
		};
		const step = createSyncDeltaStep(client);
		// Truncated JSON after the page prefix: the decoder must reject it.
		const anchored = await step(options(store, { version: 1, cursor: 'delta:page:{"state":"5"' }));
		expect(anchorGets).toBe(1);
		expect(changesCalls).toBe(0);
		expect(anchored.checkpoint.cursor).toBe('delta:state:42');
		expect(anchored.outcome).toBe('partial');
	});

	it('a page cursor with a structurally invalid payload falls back to a fresh anchor', async () => {
		const store = createMemoryOfflineStore();
		let anchorGets = 0;
		const client = {
			emailChanges: async () => ({ newState: '43', hasMoreChanges: false, created: [], updated: [], destroyed: [] }),
			emailGet: async ({ ids }: { ids: string[] }) => {
				if (ids.length === 0) anchorGets += 1;
				return { list: [], state: '42' };
			},
		};
		const step = createSyncDeltaStep(client);
		// Valid JSON, wrong shape: `pending` holds a non-string id and
		// `hasMoreChanges` is a string.
		const badPage = 'delta:page:' + JSON.stringify({ state: 5, hasMoreChanges: 'yes', pending: [7], destroyed: [] });
		const anchored = await step(options(store, { version: 1, cursor: badPage }));
		expect(anchorGets).toBe(1);
		expect(anchored.checkpoint.cursor).toBe('delta:state:42');
	});

	it('a non-cannotCalculateChanges Email/changes failure propagates', async () => {
		const store = createMemoryOfflineStore();
		const client = {
			emailChanges: async () => {
				throw new Error('server storage failure');
			},
			emailGet: async () => ({ list: [], state: '0' }),
		};
		const step = createSyncDeltaStep(client);
		await expect(step(options(store, { version: 1, cursor: 'delta:state:2' }))).rejects.toThrow('server storage failure');
	});

	it('a plain-string cannotCalculateChanges answer still maps to the blocked outcome', async () => {
		// The thrown value is not an Error and carries no type/workCode: the
		// message-based classification must still catch it.
		const store = createMemoryOfflineStore();
		const client = {
			emailChanges: async () => {
				throw 'server said: cannotCalculateChanges';
			},
			emailGet: async () => ({ list: [], state: '0' }),
		};
		const step = createSyncDeltaStep(client);
		const result = await step(options(store, { version: 1, cursor: 'delta:state:2' }));
		expect(result.outcome).toBe('blocked');
		expect(result.checkpoint.cursor).toBe('delta:state:2');
	});
});

describe('delta step application loop edges', () => {
	it('records whose id is in the outbox pending set are skipped, not applied', async () => {
		const store = createMemoryOfflineStore();
		// A queued optimistic op owns message 1: its row must not be written by
		// the server page (the F1 outbox rule applies at the step layer too).
		store.pendingMessageIds = async () => new Set(['1']);
		const client = {
			emailChanges: async () => ({ newState: '5', hasMoreChanges: false, created: ['1', '2'], updated: [], destroyed: [] }),
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: [email('1', '2026-09-01T00:00:00Z'), email('2', '2026-09-02T00:00:00Z')].filter((e) => ids.includes(e.id)),
				state: '5',
			}),
		};
		const step = createSyncDeltaStep(client);
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: FRESH_BUDGET,
			checkpoint: { version: 1, cursor: 'delta:state:0' },
		});
		// The skipped record still counts as served (charged once, never
		// re-walked), but only record 2 exists locally.
		expect(result.progress.done).toBe(2);
		expect(result.progress.chargedUnits).toBe(1);
		expect(result.outcome).toBe('complete');
		const rows = await store.listByReceivedDesc(10);
		expect(rows.map((row) => row.id)).toEqual(['2']);
	});

	it('a record id larger than the remaining byte budget stops the destroyed walk and rides the page cursor', async () => {
		const store = createMemoryOfflineStore();
		const client = {
			emailChanges: async () => ({ newState: '5', hasMoreChanges: false, created: [], updated: [], destroyed: ['a', 'b', 'c'] }),
			emailGet: async () => ({ list: [], state: '5' }),
		};
		const step = createSyncDeltaStep(client);
		// Two 1-byte ids fit a 2-byte budget; the third breaks at the ceiling.
		const stopped = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: 'delta:state:4' },
		});
		expect(stopped.outcome).toBe('partial');
		expect(stopped.progress.done).toBe(2);
		expect(stopped.checkpoint.cursor).toBe(
			`delta:page:${JSON.stringify({ state: '5', hasMoreChanges: false, pending: [], destroyed: ['c'] })}`,
		);
		// The resumed call finishes the remainder and advances the state cursor.
		const resumed = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: FRESH_BUDGET,
			checkpoint: stopped.checkpoint,
		});
		expect(resumed.outcome).toBe('complete');
		expect(resumed.checkpoint.cursor).toBe('delta:state:5');
	});

	it('an abort landing inside the destroyed walk stops it and carries the remainder', async () => {
		const store = createMemoryOfflineStore();
		const controller = new AbortController();
		const client = {
			emailChanges: async () => ({ newState: '5', hasMoreChanges: false, created: [], updated: [], destroyed: ['a', 'b'] }),
			emailGet: async () => ({ list: [], state: '5' }),
		};
		const step = createSyncDeltaStep(client);
		const originalDelete = store.deleteMessage.bind(store);
		let deletes = 0;
		store.deleteMessage = async (id: string) => {
			deletes += 1;
			controller.abort();
			await originalDelete(id);
		};
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: controller.signal,
			budget: FRESH_BUDGET,
			checkpoint: { version: 1, cursor: 'delta:state:4' },
		});
		expect(deletes).toBe(1);
		expect(result.outcome).toBe('partial');
		expect(result.checkpoint.cursor).toBe(
			`delta:page:${JSON.stringify({ state: '5', hasMoreChanges: false, pending: [], destroyed: ['b'] })}`,
		);
	});

	it('a deadline crossing inside the destroyed walk stops it and carries the remainder', async () => {
		const store = createMemoryOfflineStore();
		let mono = 0;
		const client = {
			emailChanges: async () => ({ newState: '5', hasMoreChanges: false, created: [], updated: [], destroyed: ['a', 'b'] }),
			emailGet: async () => ({ list: [], state: '5' }),
		};
		const step = createSyncDeltaStep(client, { nowMonoMs: () => mono });
		const originalDelete = store.deleteMessage.bind(store);
		let deletes = 0;
		store.deleteMessage = async (id: string) => {
			deletes += 1;
			mono = 20_000; // past the 10s budget deadline
			await originalDelete(id);
		};
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: FRESH_BUDGET,
			checkpoint: { version: 1, cursor: 'delta:state:4' },
		});
		expect(deletes).toBe(1);
		expect(result.outcome).toBe('partial');
		expect(result.checkpoint.cursor).toBe(
			`delta:page:${JSON.stringify({ state: '5', hasMoreChanges: false, pending: [], destroyed: ['b'] })}`,
		);
	});
});

describe('delta step default clock', () => {
	it('the default clock falls back to wall time where performance is absent', async () => {
		expect(typeof defaultStepClock()()).toBe('number');
		// Non-DOM shells have no performance: the factory must still produce a
		// working monotonic-scale clock (Date.now here).
		const original = globalThis.performance;
		vi.stubGlobal('performance', undefined);
		const fallback = defaultStepClock();
		expect(Math.abs(fallback() - Date.now())).toBeLessThan(1_000);
		// And a step built in such a shell runs against wall-time deadlines.
		const store = createMemoryOfflineStore();
		const client = {
			emailChanges: async () => ({ newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [] }),
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: ids.length ? [email('1', '2026-09-01T00:00:00Z')] : [],
				state: '5',
			}),
		};
		const step = createSyncDeltaStep(client);
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: Date.now() + 5_000 },
			checkpoint: { version: 1, cursor: 'delta:state:0' },
		});
		expect(result.progress.done).toBe(1);
		expect(result.outcome).toBe('complete');
		void original;
	});
});

describe('window step cursor and loop edges', () => {
	it('a foreign (non-window) checkpoint cursor restarts at position 0', async () => {
		const store = createMemoryOfflineStore();
		const positions: number[] = [];
		const client = {
			emailQuery: async (_filter: Record<string, unknown>, _sort: unknown, _limit: number, position = 0) => {
				positions.push(position);
				return { ids: ['1'] };
			},
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: ids.map((id) => email(id, '2026-09-01T00:00:00Z')),
				state: '0',
			}),
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		// A delta cursor is not a window cursor: it decodes to null and the
		// walk starts from the top instead of throwing.
		const result = await step(options(store, { version: 1, cursor: 'delta:state:4' }));
		expect(positions).toEqual([0]);
		expect(result.outcome).toBe('complete');
	});

	it('a window cursor with a negative position and a corrupt payload both restart at 0', async () => {
		const store = createMemoryOfflineStore();
		const positions: number[] = [];
		const client = {
			emailQuery: async (_filter: Record<string, unknown>, _sort: unknown, _limit: number, position = 0) => {
				positions.push(position);
				return { ids: [] };
			},
			emailGet: async () => ({ list: [], state: '0' }),
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const negative = await step(options(store, {
			version: 1,
			cursor: `window:page:${JSON.stringify({ windowCutoffMs: -1, position: -2 })}`,
		}));
		expect(negative.outcome).toBe('complete');
		const corrupt = await step(options(store, { version: 1, cursor: 'window:page:[[not-json' }));
		expect(corrupt.outcome).toBe('complete');
		// Both decoded to "no cursor": both queried at position 0.
		expect(positions).toEqual([0, 0]);
	});

	it('an empty query page completes and preserves the walk position in the cursor', async () => {
		const store = createMemoryOfflineStore();
		const client = {
			emailQuery: async () => ({ ids: [] }),
			emailGet: async () => {
				throw new Error('emailGet must not run for an empty page');
			},
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const result = await step(options(store));
		expect(result.outcome).toBe('complete');
		expect(result.progress.done).toBe(0);
		expect(result.checkpoint.cursor).toBe(`window:page:${JSON.stringify({ windowCutoffMs: -1, position: 0 })}`);
		// A resumed walk past an earlier frontier keeps its position on an
		// exhausted window.
		const resumed = await step(options(store, {
			version: 1,
			cursor: `window:page:${JSON.stringify({ windowCutoffMs: -1, position: 7 })}`,
		}));
		expect(resumed.checkpoint.cursor).toBe(`window:page:${JSON.stringify({ windowCutoffMs: -1, position: 7 })}`);
	});

	it('an aborted or expired dispatch performs no window network call', async () => {
		const store = createMemoryOfflineStore();
		let networkCalls = 0;
		const client = {
			emailQuery: async () => {
				networkCalls += 1;
				return { ids: ['1'] };
			},
			emailGet: async () => {
				networkCalls += 1;
				return { list: [], state: '0' };
			},
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const controller = new AbortController();
		controller.abort();
		const aborted = await step(options(store, { version: 1, cursor: 'window:page:x' }, controller.signal));
		expect(aborted.outcome).toBe('partial');
		expect(aborted.progress.done).toBe(0);
		// Expired monotonic deadline.
		const expired = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 0 },
			checkpoint: null,
		});
		expect(expired.outcome).toBe('partial');
		expect(networkCalls).toBe(0);
	});

	it('an abort landing after Email/query prevents the follow-up Email/get', async () => {
		const store = createMemoryOfflineStore();
		const controller = new AbortController();
		let gets = 0;
		const client = {
			emailQuery: async () => {
				controller.abort();
				return { ids: ['1', '2'] };
			},
			emailGet: async () => {
				gets += 1;
				return { list: [], state: '0' };
			},
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: controller.signal,
			budget: FRESH_BUDGET,
			checkpoint: null,
		});
		expect(gets).toBe(0);
		expect(result.outcome).toBe('partial');
		expect(result.progress.done).toBe(0);
	});

	it('an abort inside the window apply loop advances the position past the applied prefix', async () => {
		const store = createMemoryOfflineStore();
		const controller = new AbortController();
		const client = {
			emailQuery: async () => ({ ids: ['1', '2', '3'] }),
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: ids.map((id) => email(id, '2026-09-01T00:00:00Z')),
				state: '0',
			}),
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const originalApply = store.upsertMessage.bind(store);
		let writes = 0;
		store.upsertMessage = async (m: Parameters<typeof originalApply>[0]) => {
			writes += 1;
			controller.abort(); // abort after the FIRST record applied
			await originalApply(m);
		};
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: controller.signal,
			budget: FRESH_BUDGET,
			checkpoint: null,
		});
		expect(writes).toBe(1);
		expect(result.outcome).toBe('partial');
		// The frontier moved past the applied prefix: record 1 is never re-fetched.
		expect(result.checkpoint.cursor).toBe(`window:page:${JSON.stringify({ windowCutoffMs: -1, position: 1 })}`);
		// The resumed walk continues behind it.
		const queries: number[] = [];
		const resumeClient = {
			emailQuery: async (_filter: Record<string, unknown>, _sort: unknown, _limit: number, position = 0) => {
				queries.push(position);
				return { ids: ['2', '3'].slice(position - 1) };
			},
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: ids.map((id) => email(id, '2026-09-02T00:00:00Z')),
				state: '0',
			}),
		};
		const resumed = await createSyncWindowStep(resumeClient, { windowCutoffMs: null })({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: FRESH_BUDGET,
			checkpoint: result.checkpoint,
		});
		expect(queries).toEqual([1]);
		expect(resumed.outcome).toBe('complete');
		expect((await store.listByReceivedDesc(10)).map((row) => row.id).sort()).toEqual(['1', '2', '3']);
	});

	it('a deadline crossing inside the window apply loop advances the position frontier', async () => {
		const store = createMemoryOfflineStore();
		let mono = 0;
		const client = {
			emailQuery: async () => ({ ids: ['1', '2'] }),
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: ids.map((id) => email(id, '2026-09-01T00:00:00Z')),
				state: '0',
			}),
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null, nowMonoMs: () => mono });
		const originalUpsert = store.upsertMessage.bind(store);
		let writes = 0;
		store.upsertMessage = async (m: Parameters<typeof originalUpsert>[0]) => {
			writes += 1;
			mono = 20_000; // past the 10s deadline after the first write
			await originalUpsert(m);
		};
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: FRESH_BUDGET,
			checkpoint: null,
		});
		expect(writes).toBe(1);
		expect(result.outcome).toBe('partial');
		expect(result.checkpoint.cursor).toBe(`window:page:${JSON.stringify({ windowCutoffMs: -1, position: 1 })}`);
	});
});
