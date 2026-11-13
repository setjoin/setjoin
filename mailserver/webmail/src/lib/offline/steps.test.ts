import { describe, it, expect } from 'vitest';

import type { Email } from '$lib/types/jmap';
import { createSyncDeltaStep, createSyncWindowStep, isBoundedSyncStep, markBoundedSyncStep } from './steps';
import { createMemoryOfflineStore } from '$lib/native/testing/backgroundWorkHarness';
import { syncWindow } from './sync';
import type { SyncStep } from './work-contract';

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

function options(store: ReturnType<typeof createMemoryOfflineStore>, checkpoint: Parameters<SyncStep>[0]['checkpoint'] = null, signal = new AbortController().signal) {
	return { store, accountId: 'acct-1', signal, budget: BUDGET, checkpoint };
}

describe('bounded sync delta step', () => {
	it('is a branded bounded step', () => {
		const step = createSyncDeltaStep({
			emailChanges: async () => ({ newState: '1', hasMoreChanges: false, created: [], updated: [], destroyed: [] }),
			emailGet: async () => ({ list: [], state: '1' }),
		});
		expect(isBoundedSyncStep(step)).toBe(true);
		expect(isBoundedSyncStep(markBoundedSyncStep(async () => ({ checkpoint: { version: 1, cursor: null }, progress: { done: 0, chargedUnits: 0 }, outcome: 'partial' }) as never))).toBe(true);
		expect(isBoundedSyncStep(function unbounded() { return Promise.resolve({} as never); })).toBe(false);
	});

	it('re-anchors from the server state when the checkpoint is empty, then walks pages', async () => {
		const store = createMemoryOfflineStore();
		let calls = 0;
		const client = {
			emailChanges: async ({ sinceState }: { sinceState: string }) => {
				calls += 1;
				expect(sinceState).toBe(calls === 1 ? '42' : '43');
				return { newState: '43', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [] };
			},
			emailGet: async ({ ids }: { ids: string[] }) => {
				// ids=[] anchor read returns only state.
				return { list: ids.length ? [email('1', '2026-09-01T00:00:00Z')] : [], state: '42' };
			},
		};
		const step = createSyncDeltaStep(client);
		const anchored = await step(options(store));
		expect(anchored.outcome).toBe('partial');
		expect(anchored.checkpoint.cursor).toBe('delta:state:42');
		const walked = await step(options(store, anchored.checkpoint));
		expect(walked.outcome).toBe('complete');
		expect(walked.checkpoint.cursor).toBe('delta:state:43');
	});

	it('never advances the cursor past records that were not applied', async () => {
		const store = createMemoryOfflineStore();
		store.failNextMerge(new Error('local write failed'));
		const client = {
			emailChanges: async () => ({ newState: '9', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [] }),
			emailGet: async () => ({ list: [email('1', '2026-09-01T00:00:00Z')], state: '9' }),
		};
		const step = createSyncDeltaStep(client);
		await expect(step(options(store, { version: 1, cursor: 'delta:state:8' }))).rejects.toThrow('local write failed');
	});

	// E4-I Astra r2 finding 8: a mid-page budget stop makes FORWARD progress —
	// the applied prefix is charged once and the remainder rides the page
	// cursor, so the next call never re-applies the same records.
	it('stops at the budget deadline between records and carries the remainder forward', async () => {
		const store = createMemoryOfflineStore();
		let mono = 0;
		const gets: string[][] = [];
		const client = {
			emailChanges: async () => ({ newState: '5', hasMoreChanges: true, created: ['1', '2', '3'], updated: [], destroyed: [] }),
			emailGet: async ({ ids }: { ids: string[] }) => {
				gets.push([...ids]);
				return { list: [email('1', '2026-09-01T00:00:00Z'), email('2', '2026-09-02T00:00:00Z'), email('3', '2026-09-03T00:00:00Z')].filter((e) => ids.includes(e.id)), state: '5' };
			},
		};
		const step = createSyncDeltaStep(client, { nowMonoMs: () => mono });
		// The deadline passes after the first record is applied.
		const originalMerge = store.mergeServerDelta.bind(store);
		let merges = 0;
		store.mergeServerDelta = async (...args) => {
			merges += 1;
			mono = merges >= 2 ? 20_000 : 0;
			return originalMerge(...args);
		};
		// Start from an anchored cursor so the walk enters the page directly,
		// with a 10-second budget on the injected monotonic clock scale.
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: 'delta:state:0' },
		});
		expect(merges).toBe(2);
		expect(result.outcome).toBe('partial');
		// The unapplied record rides the page cursor: the state did NOT advance,
		// but the frontier moved past the two applied records.
		expect(result.checkpoint.cursor).toBe(`delta:page:${JSON.stringify({ state: '5', hasMoreChanges: true, pending: ['3'], destroyed: [] })}`);
		// The resumed call works ONLY the remainder — records 1 and 2 are never
		// fetched or charged again — and completes the page.
		mono = 0; // a fresh budget window for the resumed dispatch
		const resumed = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 },
			checkpoint: result.checkpoint,
		});
		expect(resumed.outcome).toBe('partial');
		expect(resumed.checkpoint.cursor).toBe('delta:state:5');
		expect(gets[1]).toEqual(['3']);
		expect(merges).toBe(3);
		expect((await store.listByReceivedDesc(10)).map((row) => row.id).sort()).toEqual(['1', '2', '3']);
	});

	// Astra r2 finding 8 exact trace: two individually fitting records, a byte
	// budget fitting only one — record A is applied ONCE, record B progresses.
	it('a byte budget fitting one of two records applies each record exactly once', async () => {
		const store = createMemoryOfflineStore();
		const oneRecordBytes = JSON.stringify(email('1', '2026-09-01T00:00:00Z')).length + 64;
		let changesCalls = 0;
		const client = {
			emailChanges: async () => {
				changesCalls += 1;
				return { newState: '5', hasMoreChanges: false, created: ['1', '2'], updated: [], destroyed: [] };
			},
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: [email('1', '2026-09-01T00:00:00Z'), email('2', '2026-09-02T00:00:00Z')].filter((e) => ids.includes(e.id)),
				state: '5',
			}),
		};
		const step = createSyncDeltaStep(client);
		const first = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: oneRecordBytes, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: 'delta:state:0' },
		});
		expect(first.progress.done).toBe(1);
		expect(first.checkpoint.cursor).toContain('delta:page:');
		// The resumed page needs no second Email/changes round-trip.
		const second = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 },
			checkpoint: first.checkpoint,
		});
		expect(second.outcome).toBe('complete');
		expect(changesCalls).toBe(1);
		expect((await store.listByReceivedDesc(10)).map((row) => row.id).sort()).toEqual(['1', '2']);
	});

	it('replays idempotently: re-applying the same page does not duplicate rows', async () => {
		const store = createMemoryOfflineStore();
		const make = () => ({
			emailChanges: async () => ({ newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [] }),
			emailGet: async () => ({ list: [email('1', '2026-09-01T00:00:00Z')], state: '5' }),
		});
		const first = await createSyncDeltaStep(make())(options(store));
		const second = await createSyncDeltaStep(make())(options(store, first.checkpoint));
		expect(second.outcome).toBe('complete');
		expect((await store.listByReceivedDesc(10)).filter((row) => row.id === '1')).toHaveLength(1);
	});

	// Astra finding 9: the byte budget is a hard per-call ceiling.
	it('a one-byte budget accepts no record at all', async () => {
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
			budget: { maxRecords: 64, maxBytes: 1, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: 'delta:state:0' },
		});
		// The 5KB record never fit the 1-byte budget: nothing applied, progress
		// zero — and the unapplied record is carried on the page cursor (the
		// state anchor does not advance past unapplied work).
		expect(result.progress.done).toBe(0);
		expect(result.checkpoint.cursor).toBe(`delta:page:${JSON.stringify({ state: '5', hasMoreChanges: false, pending: ['1'], destroyed: [] })}`);
		expect((await store.listByReceivedDesc(10))).toHaveLength(0);
	});

	// Astra r6 finding 4: an EXHAUSTED byte allowance issues no network call
	// at all — Email/changes used to run before the zero-budget check, so an
	// exhausted dispatch kept fetching metadata it could never apply.
	it('an exhausted byte budget performs no network call from a state cursor (r6)', async () => {
		const store = createMemoryOfflineStore();
		let networkCalls = 0;
		const client = {
			emailChanges: async () => {
				networkCalls += 1;
				return { newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [] };
			},
			emailGet: async () => {
				networkCalls += 1;
				return { list: [], state: '5' };
			},
		};
		const step = createSyncDeltaStep(client);
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 0, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: 'delta:state:4' },
		});
		expect(networkCalls).toBe(0);
		expect(result.outcome).toBe('partial');
		expect(result.progress.done).toBe(0);
		expect(result.progress.appliedBytes).toBe(0);
		// The prior cursor is returned unchanged — the remainder stays where it
		// was so a refilled dispatch resumes from exactly this frontier.
		expect(result.checkpoint.cursor).toBe('delta:state:4');
	});

	it('an exhausted byte budget performs no network call from a page cursor (r6)', async () => {
		const store = createMemoryOfflineStore();
		let networkCalls = 0;
		const client = {
			emailChanges: async () => {
				networkCalls += 1;
				return { newState: '5', hasMoreChanges: false, created: [], updated: [], destroyed: [] };
			},
			emailGet: async () => {
				networkCalls += 1;
				return { list: [], state: '5' };
			},
		};
		const step = createSyncDeltaStep(client);
		const pageCursor = `delta:page:${JSON.stringify({ state: '5', hasMoreChanges: true, pending: ['1', '2'], destroyed: ['3'] })}`;
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 0, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: pageCursor },
		});
		expect(networkCalls).toBe(0);
		expect(result.outcome).toBe('partial');
		// The page cursor still carries the unapplied remainder.
		expect(result.checkpoint.cursor).toBe(pageCursor);
	});

	// Astra r8 finding (P2): the initial Email/get anchor is itself a network
	// call — it used to run BEFORE the abort/deadline/zero-byte guards, so an
	// exhausted (or aborted/expired) dispatch with no committed checkpoint
	// still paid one round-trip. The guards now precede the re-anchor.
	it('the initial anchor issues no network call when aborted, expired, or zero-budget (r9)', async () => {
		const store = createMemoryOfflineStore();
		let networkCalls = 0;
		const client = {
			emailChanges: async () => {
				networkCalls += 1;
				return { newState: '5', hasMoreChanges: false, created: [], updated: [], destroyed: [] };
			},
			emailGet: async () => {
				networkCalls += 1;
				return { list: [], state: '5' };
			},
		};
		const step = createSyncDeltaStep(client);
		// Zero budget with a NULL checkpoint: the old code anchored first and
		// only then hit the zero-byte guard — one network call for nothing.
		const zeroBudget = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 0, deadlineMonoMs: 10_000 },
			checkpoint: null,
		});
		expect(networkCalls).toBe(0);
		expect(zeroBudget.outcome).toBe('partial');
		expect(zeroBudget.progress.done).toBe(0);
		expect(zeroBudget.progress.appliedBytes).toBe(0);
		// No anchor was committed: the next refilled dispatch re-attempts it.
		expect(zeroBudget.checkpoint.cursor).toBeNull();

		// Aborted before the call.
		const controller = new AbortController();
		controller.abort();
		const aborted = await step({
			store,
			accountId: 'acct-1',
			signal: controller.signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 },
			checkpoint: null,
		});
		expect(networkCalls).toBe(0);
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
		expect(networkCalls).toBe(0);
		expect(expired.outcome).toBe('partial');
		expect(expired.progress.done).toBe(0);
	});

	it('cancellation observed during Email/changes prevents the follow-up Email/get', async () => {
		const store = createMemoryOfflineStore();
		const controller = new AbortController();
		let emailGetCalls = 0;
		const client = {
			emailChanges: async () => {
				// The abort lands while Email/changes is in flight.
				controller.abort();
				return { newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [] };
			},
			emailGet: async () => {
				emailGetCalls += 1;
				return { list: [email('1', '2026-09-01T00:00:00Z')], state: '5' };
			},
		};
		const step = createSyncDeltaStep(client);
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: controller.signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: 'delta:state:0' },
		});
		expect(emailGetCalls).toBe(0);
		expect(result.outcome).toBe('partial');
		expect(result.progress.done).toBe(0);
	});

	it('the default clock is monotonic performance time, so monotonic deadlines do not read as expired', async () => {
		const store = createMemoryOfflineStore();
		const client = {
			emailChanges: async () => ({ newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [] }),
			emailGet: async () => ({ list: [email('1', '2026-09-01T00:00:00Z')], state: '5' }),
		};
		// No injected clock: the deadline is a monotonic performance value. The
		// old Date.now() default sat ~1.7e12 ms above that origin and made every
		// step an immediate no-progress result.
		const step = createSyncDeltaStep(client);
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: performance.now() + 5_000 },
			checkpoint: { version: 1, cursor: 'delta:state:0' },
		});
		expect(result.progress.done).toBe(1);
		expect(result.outcome).toBe('complete');
	});

	// Astra finding 14: cannotCalculateChanges is the blocked outcome, never a
	// thrown terminal failure.
	it('a cannotCalculateChanges answer maps to the blocked outcome with the prior cursor', async () => {
		const store = createMemoryOfflineStore();
		const client = {
			emailChanges: async () => {
				throw Object.assign(new Error('cannotCalculateChanges'), { type: 'cannotCalculateChanges' });
			},
			emailGet: async () => ({ list: [], state: '0' }),
		};
		const step = createSyncDeltaStep(client);
		const result = await step(options(store, { version: 1, cursor: 'delta:state:2' }));
		expect(result.outcome).toBe('blocked');
		expect(result.checkpoint.cursor).toBe('delta:state:2');
		expect(result.progress.done).toBe(0);
	});
});

describe('bounded sync window step', () => {
	it('pages newest-first by position and completes on a short page', async () => {
		const store = createMemoryOfflineStore();
		const ids = Array.from({ length: 70 }, (_, index) => `id-${index}`);
		const client = {
			emailQuery: async (_filter: Record<string, unknown>, _sort: unknown, limit: number, position = 0) => ({
				ids: ids.slice(position, position + limit),
			}),
			emailGet: async ({ ids: requested }: { ids: string[] }) => ({
				list: requested.map((id) => email(id, '2026-09-01T00:00:00Z')),
				state: '0',
			}),
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const page1 = await step(options(store));
		expect(page1.outcome).toBe('partial');
		expect(page1.progress.done).toBe(64);
		const page2 = await step(options(store, page1.checkpoint));
		expect(page2.outcome).toBe('complete');
		expect(page2.progress.done).toBe(6);
		const rows = await store.listByReceivedDesc(200);
		expect(rows).toHaveLength(70);
	});

	it('restarts the walk when the window changed under the checkpoint', async () => {
		const store = createMemoryOfflineStore();
		const queries: Array<Record<string, unknown>> = [];
		const client = {
			emailQuery: async (filter: Record<string, unknown>, _sort: unknown, limit: number, position = 0) => {
				queries.push({ ...filter, position });
				return { ids: ['1'] };
			},
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: ids.map((id) => email(id, '2026-09-01T00:00:00Z')),
				state: '0',
			}),
		};
		const cutoff = Date.parse('2026-08-18T00:00:00Z');
		const step = createSyncWindowStep(client, { windowCutoffMs: cutoff });
		const first = await step(options(store));
		expect(queries[0]).toMatchObject({ position: 0 });
		// A different window invalidates the checkpoint: position restarts at 0.
		const changedStep = createSyncWindowStep(client, { windowCutoffMs: cutoff - 86_400_000 });
		await changedStep(options(store, first.checkpoint));
		expect(queries[1]).toMatchObject({ position: 0 });
		expect(queries[1].after).toBeDefined();
	});

	// Astra finding 9: the window step enforces the same hard byte ceiling.
	it('a window page with a one-byte budget applies no record', async () => {
		const store = createMemoryOfflineStore();
		const client = {
			emailQuery: async () => ({ ids: ['1'] }),
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: ids.map((id) => email(id, '2026-09-01T00:00:00Z')),
				state: '0',
			}),
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 1, deadlineMonoMs: 10_000 },
			checkpoint: null,
		});
		expect(result.progress.done).toBe(0);
		expect((await store.listByReceivedDesc(10))).toHaveLength(0);
	});

	// Astra r6 finding 4: the window step used to run Email/query (and then
	// Email/get) BEFORE its zero-budget check, so an exhausted dispatch
	// re-queried every loop until the time deadline.
	it('an exhausted byte budget performs no network call (window, r6)', async () => {
		const store = createMemoryOfflineStore();
		let networkCalls = 0;
		const client = {
			emailQuery: async () => {
				networkCalls += 1;
				return { ids: ['1', '2'] };
			},
			emailGet: async () => {
				networkCalls += 1;
				return { list: [], state: '0' };
			},
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const pageCursor = `window:page:${JSON.stringify({ windowCutoffMs: -1, position: 3 })}`;
		const result = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 0, deadlineMonoMs: 10_000 },
			checkpoint: { version: 1, cursor: pageCursor },
		});
		expect(networkCalls).toBe(0);
		expect(result.outcome).toBe('partial');
		expect(result.progress.done).toBe(0);
		expect(result.progress.appliedBytes).toBe(0);
		// The unchanged position cursor carries the remainder.
		expect(result.checkpoint.cursor).toBe(pageCursor);
	});

	// Astra r2 finding 8: the window step makes the same forward progress — the
	// position advances past the applied prefix instead of re-fetching it.
	it('a window byte budget fitting one of two records advances the position frontier', async () => {
		const store = createMemoryOfflineStore();
		const oneRecordBytes = JSON.stringify(email('1', '2026-09-01T00:00:00Z')).length + 64;
		const queries: number[] = [];
		const client = {
			emailQuery: async (_filter: Record<string, unknown>, _sort: unknown, _limit: number, position = 0) => {
				queries.push(position);
				return { ids: ['1', '2'].slice(position) };
			},
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: [email('1', '2026-09-01T00:00:00Z'), email('2', '2026-09-02T00:00:00Z')].filter((e) => ids.includes(e.id)),
				state: '0',
			}),
		};
		const step = createSyncWindowStep(client, { windowCutoffMs: null });
		const first = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: oneRecordBytes, deadlineMonoMs: 10_000 },
			checkpoint: null,
		});
		expect(first.progress.done).toBe(1);
		expect(first.checkpoint.cursor).toContain('window:page:');
		// The second call queries at position 1: record '1' is never re-applied.
		const second = await step({
			store,
			accountId: 'acct-1',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 },
			checkpoint: first.checkpoint,
		});
		expect(queries).toEqual([0, 1]);
		expect(second.outcome).toBe('complete');
		expect((await store.listByReceivedDesc(10)).map((row) => row.id).sort()).toEqual(['1', '2']);
	});
});

describe('wrapper compatibility', () => {
	it('syncWindow remains a wrapper that does not carry the bounded-step brand', () => {
		expect(isBoundedSyncStep(syncWindow as unknown as SyncStep)).toBe(false);
	});
});
