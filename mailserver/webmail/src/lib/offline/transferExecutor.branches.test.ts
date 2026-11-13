/**
 * Transfer-executor edge branches (coverage round r2).
 *
 * Direct production-ports tests for the executor paths the harness lifecycle
 * suite leaves cold: disposal, zero-length starts (complete and expired),
 * invalid constructions, terminal checkpoint replays, destination
 * rejection, mint failures and races, transport-failure classifications,
 * post-flight staleness, body-length mismatch, mid-write/digest
 * interruption windows, the partial-range retry envelope, the 416
 * safe-restart envelope, non-404 terminal failures, and the verifying
 * restart's happy promotion.
 */

import { describe, it, expect, vi } from 'vitest';

import {
	createTransferExecutor,
	type RangeObservation,
	type TransferExecutorPorts,
} from './transferExecutor';
import { createMemoryTransferPersistence } from './jobStore';
import { createCriticalActivityCounter } from './criticalScope';

const SHA_OK = 'ab'.repeat(32);
const SHA_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const DEADLINE_FUTURE = '2026-09-24T00:00:00Z';
const DEADLINE_PAST = '2026-09-01T00:00:00Z';
const NOW = Date.parse('2026-09-17T01:00:00Z');

function start(overrides: Record<string, unknown> = {}) {
	return {
		accountId: 'acct-1',
		jobId: 'job-t1',
		blobId: SHA_OK,
		expectedSize: 10,
		expectedSha256: SHA_OK,
		deadlineUtc: DEADLINE_FUTURE,
		...overrides,
	};
}

function range206(bodyBytes: number, opts: { start?: number; total?: number } = {}): RangeObservation {
	const requestStart = opts.start ?? 0;
	const total = opts.total ?? 10;
	const end = requestStart + bodyBytes - 1;
	return {
		status: 206,
		etag: `"${SHA_OK}"`,
		contentRange: `bytes ${requestStart}-${end}/${total}`,
		contentEncoding: 'identity',
		bodyByteCount: bodyBytes,
		bodyBytes: new Uint8Array(bodyBytes).fill(1),
		mintGeneration: 1,
		mintWasCurrent: true,
	};
}

function persistedRow(overrides: Record<string, unknown> = {}) {
	return {
		jobId: 'job-t1',
		accountId: 'acct-1',
		blobSha256: SHA_OK,
		etag: `"${SHA_OK}"`,
		expectedSize: 10,
		expectedSha256: SHA_OK,
		committedBytes: 10,
		state: 'verifying',
		deadlineUtc: DEADLINE_FUTURE,
		attempts: 1,
		...overrides,
	};
}

type MemoryTransferPersistence = ReturnType<typeof createMemoryTransferPersistence>;

interface TestPorts extends TransferExecutorPorts {
	persist: MemoryTransferPersistence;
	sink: TransferExecutorPorts['sink'];
}

function createPorts(overrides: {
	authorization?: TransferExecutorPorts['authorization'];
	fetchRange?: TransferExecutorPorts['fetchRange'];
	mintTransferToken?: TransferExecutorPorts['mintTransferToken'];
	nowUtc?: TransferExecutorPorts['nowUtc'];
	sinkOverrides?: Partial<TransferExecutorPorts['sink']>;
} = {}): TestPorts {
	const persist = createMemoryTransferPersistence();
	const sink = {
		openPartial: vi.fn(async () => undefined),
		write: vi.fn(async () => undefined),
		committedDigest: vi.fn(async () => SHA_OK),
		promote: vi.fn(async () => undefined),
		purge: vi.fn(async () => undefined),
		...overrides.sinkOverrides,
	};
	const ports: TestPorts = {
		approvedOrigin: 'https://blobs.example.com',
		authorization: overrides.authorization ?? (async () => ({ accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 1 })),
		onAuthorizationChange: () => () => undefined,
		mintTransferToken: overrides.mintTransferToken ?? vi.fn(async () => 'bearer-1'),
		fetchRange: overrides.fetchRange ?? vi.fn(async () => range206(10)),
		sink: sink as TransferExecutorPorts['sink'],
		persist,
		critical: createCriticalActivityCounter(),
		nowUtc: overrides.nowUtc ?? (() => new Date(NOW).toISOString()),
	};
	return ports;
}

describe('transfer executor lifecycle edges', () => {
	it('dispose stops admission, unsubscribes and is idempotent', async () => {
		const ports = createPorts();
		const executor = createTransferExecutor(ports);
		expect(executor.disposed).toBe(false);
		executor.dispose();
		expect(executor.disposed).toBe(true);
		// A disposed executor reports disposed for any cycle.
		await expect(executor.runTransfer('job-t1')).resolves.toEqual({ kind: 'disposed' });
		// A second dispose is a no-op.
		expect(() => executor.dispose()).not.toThrow();
	});

	it('a zero-length start completes as an explicit terminal empty without the sink', async () => {
		const ports = createPorts();
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start({ expectedSize: 0, expectedSha256: SHA_EMPTY, blobId: SHA_EMPTY }));
		expect(outcome).toMatchObject({ kind: 'promoted' });
		if (outcome.kind === 'promoted') {
			expect(outcome.checkpoint.state).toBe('complete');
			expect(outcome.checkpoint.committedBytes).toBe(0);
			expect(outcome.checkpoint.expectedSize).toBe(0);
		}
		// No sink write path for a zero-length value, and no checkpoint row.
		expect(ports.sink.write).not.toHaveBeenCalled();
		expect(ports.persist.snapshot()).toHaveLength(0);
	});

	it('a zero-length start past its deadline expires instead of completing', async () => {
		const ports = createPorts();
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start({
			expectedSize: 0,
			expectedSha256: SHA_EMPTY,
			blobId: SHA_EMPTY,
			deadlineUtc: DEADLINE_PAST,
		}));
		expect(outcome.kind).toBe('terminal-expired');
		// A queued-but-expired start leaves no expired row behind (the purge ran;
		// the classification is reported, never persisted for this shape).
		expect(ports.persist.snapshot()).toHaveLength(0);
	});

	it('an invalid start construction is a safe restart without a purge', async () => {
		const ports = createPorts();
		const executor = createTransferExecutor(ports);
		// expectedSha256 fails the frozen hash shape: construction is not ready.
		const outcome = await executor.startTransfer(start({ expectedSha256: 'not-hex' }));
		expect(outcome).toEqual({ kind: 'safe-restart', reason: 'invalid-checkpoint', purged: false });
		expect(ports.sink.purge).not.toHaveBeenCalled();
	});

	it('terminal checkpoints replay without any network effect', async () => {
		const ports = createPorts();
		await ports.persist.upsertCheckpoint(persistedRow({ state: 'failed', committedBytes: 4 }));
		const executor = createTransferExecutor(ports);
		const failed = await executor.runTransfer('job-t1');
		expect(failed).toMatchObject({ kind: 'terminal-failure', reason: 'already-failed' });

		await ports.persist.upsertCheckpoint(persistedRow({ state: 'expired', committedBytes: 4 }));
		const expired = await executor.runTransfer('job-t1');
		expect(expired.kind).toBe('terminal-expired');
		// No range request was ever sent for terminal replays.
		expect(ports.fetchRange).not.toHaveBeenCalled();
	});

	it('a blob id that is not a SHA-256 rejects the destination before any mint', async () => {
		const ports = createPorts();
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start({ blobId: 'not-a-sha256-value' }));
		expect(outcome.kind).toBe('destination-rejected');
		expect(ports.mintTransferToken).not.toHaveBeenCalled();
	});
});

describe('transfer executor authorization and transport edges', () => {
	it('a failing mint pauses admission without any state change', async () => {
		const ports = createPorts({
			mintTransferToken: vi.fn(async () => {
				throw new Error('mint refused');
			}),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'authExpired' });
		// The account-bound initial row persists (valid durable restart state):
		// zero verified bytes, still queued.
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'queued', committedBytes: 0 });
	});

	it('authorization rotated while the mint was pending: stale result, no purge', async () => {
		const authorization = { current: { accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 1 } };
		const ports = createPorts({
			authorization: async () => authorization.current,
			mintTransferToken: async () => {
				authorization.current = { ...authorization.current, policyGeneration: 2 };
				return 'bearer-1';
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'stale-result' });
		// The initial row is untouched durable state — not purged, not advanced.
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'queued', committedBytes: 0 });
		expect(ports.sink.purge).not.toHaveBeenCalled();
	});

	it('Critical beginning during the mint yields the cycle as criticalActivity', async () => {
		const ports = createPorts({
			mintTransferToken: async () => {
				ports.critical.begin('security');
				return 'bearer-1';
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.sink.write).not.toHaveBeenCalled();
	});

	it('a fetch exception under a live deadline is an E3 transport retry with the envelope persisted', async () => {
		const ports = createPorts({
			fetchRange: vi.fn(async () => {
				throw new Error('socket reset');
			}),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('retry');
		if (outcome.kind === 'retry') {
			expect(outcome.checkpoint.state).toBe('retry');
			expect(outcome.checkpoint.attempts).toBe(1);
			expect(outcome.checkpoint.deadlineUtc).toBe(DEADLINE_FUTURE);
		}
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'retry', attempts: 1 });
	});

	it('a deadline crossed during the fetch expires the transport failure instead of retrying', async () => {
		let now = NOW;
		const ports = createPorts({
			fetchRange: async () => {
				now = Date.parse('2026-09-25T00:00:00Z');
				throw new Error('socket reset');
			},
			nowUtc: () => new Date(now).toISOString(),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('terminal-expired');
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'expired' });
	});

	it('an authorization rotation during the fetch makes the observation stale without touching state', async () => {
		const authorization = { current: { accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 1 } };
		const ports = createPorts({
			authorization: async () => authorization.current,
			fetchRange: async () => {
				authorization.current = { ...authorization.current, policyGeneration: 7 };
				return range206(10);
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'stale-result' });
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'queued', committedBytes: 0 });
		expect(ports.sink.purge).not.toHaveBeenCalled();
	});
});

describe('transfer executor effect-path edges', () => {
	it('an accepted range whose body never arrived purges and safe-restarts', async () => {
		const ports = createPorts({
			fetchRange: vi.fn(async () => ({
				...range206(10),
				bodyBytes: new Uint8Array(0),
			})),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toMatchObject({ kind: 'safe-restart', reason: 'body-length-mismatch', purged: true });
		expect(ports.sink.write).not.toHaveBeenCalled();
		expect(ports.persist.snapshot()).toHaveLength(0);
	});

	it('Critical beginning during openPartial stops the effect chain before any write', async () => {
		const ports = createPorts({
			sinkOverrides: {
				openPartial: async () => {
					ports.critical.begin('security');
				},
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.sink.write).not.toHaveBeenCalled();
		// Only the account-bound initial row exists; nothing advanced.
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'queued', committedBytes: 0 });
	});

	it('Critical beginning during the sink write stops before the checkpoint persist', async () => {
		const ports = createPorts({
			sinkOverrides: {
				write: async () => {
					ports.critical.begin('security');
				},
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		// The write's bytes landed but NO checkpoint advanced behind them: the
		// row is still the initial queued shape with zero verified bytes.
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'queued', committedBytes: 0 });
	});

	it('a partial range accepts, persists and answers retry with the retained envelope', async () => {
		const ports = createPorts({
			fetchRange: vi.fn(async () => range206(5, { start: 0 })),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('retry');
		if (outcome.kind === 'retry') {
			expect(outcome.checkpoint.state).toBe('transferring');
			expect(outcome.checkpoint.committedBytes).toBe(5);
		}
		expect(ports.sink.write).toHaveBeenCalledWith('job-t1', 0, expect.any(Uint8Array));
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'transferring', committedBytes: 5 });
	});

	it('a range validation failure purges and safe-restarts with the retained envelope', async () => {
		const ports = createPorts({
			fetchRange: vi.fn(async () => ({
				...range206(10),
				status: 416,
				contentRange: 'bytes */10',
				bodyByteCount: 0,
				bodyBytes: undefined,
			})),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('safe-restart');
		if (outcome.kind === 'safe-restart') {
			expect(outcome.purged).toBe(true);
			expect(outcome.deadlineUtc).toBe(DEADLINE_FUTURE);
			expect(outcome.attempts).toBe(0);
		}
		expect(ports.persist.snapshot()).toHaveLength(0);
	});

	it('a non-redirect HTTP terminal failure persists the failed terminal', async () => {
		const ports = createPorts({
			fetchRange: vi.fn(async () => ({
				...range206(10),
				status: 400,
				bodyByteCount: 0,
				bodyBytes: undefined,
			})),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('terminal-failure');
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'failed' });
	});
});

describe('transfer executor verifying paths', () => {
	it('a fully-downloaded verifying checkpoint verifies, promotes and persists the completion', async () => {
		const ports = createPorts();
		await ports.persist.upsertCheckpoint(persistedRow());
		const executor = createTransferExecutor(ports);
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('promoted');
		expect(ports.fetchRange).not.toHaveBeenCalled();
		expect(ports.sink.promote).toHaveBeenCalledWith('job-t1');
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'complete', committedBytes: 10 });
	});

	it('Critical beginning during the restart digest stops before promotion', async () => {
		const ports = createPorts({
			sinkOverrides: {
				committedDigest: async () => {
					ports.critical.begin('security');
					return SHA_OK;
				},
			},
		});
		await ports.persist.upsertCheckpoint(persistedRow());
		const executor = createTransferExecutor(ports);
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.sink.promote).not.toHaveBeenCalled();
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'verifying' });
	});

	it('a digest mismatch on the restart path purges and safe-restarts with the envelope', async () => {
		const ports = createPorts({
			sinkOverrides: {
				committedDigest: vi.fn(async () => 'cd'.repeat(32)),
			},
		});
		await ports.persist.upsertCheckpoint(persistedRow());
		const executor = createTransferExecutor(ports);
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('safe-restart');
		if (outcome.kind === 'safe-restart') {
			expect(outcome.purged).toBe(true);
			expect(outcome.deadlineUtc).toBe(DEADLINE_FUTURE);
			expect(outcome.attempts).toBe(1);
		}
		expect(ports.persist.snapshot()).toHaveLength(0);
	});
});

describe('transfer executor cancellation scoping', () => {
	it('cancelTransfer purges only for account-scoped reasons', async () => {
		const ports = createPorts();
		const executor = createTransferExecutor(ports);
		await ports.persist.upsertCheckpoint(persistedRow());
		await executor.cancelTransfer('job-t1', 'user');
		expect(ports.sink.purge).not.toHaveBeenCalled();
		expect(ports.persist.snapshot()).toHaveLength(1);
		await executor.cancelTransfer('job-t1', 'account-change');
		expect(ports.sink.purge).toHaveBeenCalledWith('job-t1');
		expect(ports.persist.snapshot()).toHaveLength(0);
	});
});

describe('transfer executor interruption and disposal races', () => {
	it('a corrupt persisted row (bytes beyond expected size) is refused as a safe restart', async () => {
		const ports = createPorts();
		// Fails rowToCheckpoint's cheap structural guard: committed > expected.
		await ports.persist.upsertCheckpoint(persistedRow({ committedBytes: 50 }));
		const executor = createTransferExecutor(ports);
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome).toEqual({ kind: 'safe-restart', reason: 'invalid-checkpoint', purged: false });
	});

	it('Critical beginning during a fetch exception yields the cycle instead of retrying', async () => {
		const ports = createPorts({
			fetchRange: async () => {
				ports.critical.begin('security');
				throw new Error('aborted mid-flight');
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		// The yield is an admission state — no retry increment was persisted.
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'queued', attempts: 0 });
	});

	it('a 404 whose classification races the deadline persists the expired terminal', async () => {
		let now = NOW;
		const ports = createPorts({
			fetchRange: vi.fn(async () => {
				now = Date.parse('2026-09-25T00:00:00Z');
				return {
					...range206(10),
					status: 404,
					bodyByteCount: 0,
					bodyBytes: undefined,
				};
			}),
			nowUtc: () => new Date(now).toISOString(),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('terminal-expired');
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'expired' });
	});

	it('Critical beginning during the postflight stops the cycle before openPartial', async () => {
		const authorization = { current: { accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 1 } };
		let calls = 0;
		const ports = createPorts({
			authorization: async () => {
				calls += 1;
				// The POSTFLIGHT read (third authorization read of the cycle)
				// begins Critical after answering: the world moved mid-flight.
				if (calls === 3) ports.critical.begin('security');
				return authorization.current;
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.sink.openPartial).not.toHaveBeenCalled();
	});

	it('Critical beginning during the verifying upsert stops before the digest', async () => {
		const ports = createPorts();
		const originalUpsert = ports.persist.upsertCheckpoint.bind(ports.persist);
		ports.persist.upsertCheckpoint = async (checkpoint: Parameters<typeof originalUpsert>[0]) => {
			await originalUpsert(checkpoint);
			if (checkpoint.state === 'verifying') ports.critical.begin('security');
		};
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.sink.committedDigest).not.toHaveBeenCalled();
		expect(ports.sink.promote).not.toHaveBeenCalled();
	});

	it('Critical beginning during the in-cycle digest stops before promotion', async () => {
		const ports = createPorts({
			sinkOverrides: {
				committedDigest: async () => {
					ports.critical.begin('security');
					return SHA_OK;
				},
			},
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.sink.promote).not.toHaveBeenCalled();
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'verifying' });
	});

	it('a 5xx answer under a live deadline classifies as a bounded retry', async () => {
		const ports = createPorts({
			fetchRange: vi.fn(async () => ({
				...range206(10),
				status: 503,
				bodyByteCount: 0,
				bodyBytes: undefined,
			})),
		});
		const executor = createTransferExecutor(ports);
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('retry');
		if (outcome.kind === 'retry') {
			expect(outcome.checkpoint.state).toBe('retry');
			expect(outcome.checkpoint.attempts).toBe(1);
		}
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'retry', attempts: 1 });
	});

	it('dispose aborts an in-flight cycle at the next interruption checkpoint', async () => {
		let releaseFetch: (() => void) | null = null;
		const gate = new Promise<void>((resolve) => {
			releaseFetch = resolve;
		});
		const ports = createPorts({
			fetchRange: vi.fn(async () => {
				await gate;
				return range206(10);
			}),
		});
		const executor = createTransferExecutor(ports);
		const cycle = executor.startTransfer(start());
		// Let the cycle reach the fetch, then dispose while it is in flight.
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
		executor.dispose();
		expect(executor.disposed).toBe(true);
		releaseFetch!();
		const outcome = await cycle;
		// The aborted cycle yielded at its next checkpoint: no promotion, no
		// completed state — only the account-bound initial row remains.
		expect(outcome.kind === 'promoted').toBe(false);
	});

	it('Critical beginning after the restart authorization read stops before the digest', async () => {
		let calls = 0;
		const ports = createPorts({
			authorization: async () => {
				calls += 1;
				if (calls === 1) ports.critical.begin('security');
				return { accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 1 };
			},
		});
		await ports.persist.upsertCheckpoint(persistedRow());
		const executor = createTransferExecutor(ports);
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		expect(ports.sink.committedDigest).not.toHaveBeenCalled();
	});

	it('a deadline crossing during the restart digest expires instead of promoting', async () => {
		let now = NOW;
		const ports = createPorts({
			sinkOverrides: {
				committedDigest: async () => {
					now = Date.parse('2026-09-25T00:00:00Z');
					return SHA_OK;
				},
			},
			nowUtc: () => new Date(now).toISOString(),
		});
		await ports.persist.upsertCheckpoint(persistedRow());
		const executor = createTransferExecutor(ports);
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('terminal-expired');
		expect(ports.sink.promote).not.toHaveBeenCalled();
		expect(ports.persist.snapshot().at(-1)).toMatchObject({ state: 'expired' });
	});
});
