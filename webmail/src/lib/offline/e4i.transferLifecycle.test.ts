/**
 * CAS-E4I-TRANSFER-LIFECYCLE — E4-I verification binding (core lane).
 *
 * Real controller-to-effect/sink wiring through the E3 pure decisions:
 * restart/expiry remint under current authorization, unmount/re-entry, account
 * change, revocation cleanup, stale hidden/confirmed results, redirect
 * rejection, and sanitized persistence inspection (no bearer or URL retained).
 *
 * E4-I Astra corrections under test: the receipt derives every oracle field
 * from ACTUAL run observations and is written ONCE in afterAll; the
 * resurrection trace (revoke during a pending mint) can no longer reach
 * fetch/write/promote/persist; account identity gates every terminal path
 * (including completed-checkpoint replay and zero-length completion); a raw
 * current-mint 404/410 preserves state instead of purging; lifecycle-aware
 * restart never re-fetches a fully-downloaded or expired transfer; fetch
 * exceptions classify as E3 transport retries carrying the retained
 * deadline/attempt envelope.
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';

import {
	auditTransferLifecycle,
	createHarnessExecutor,
	e4iFailure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
	type HarnessExecutor,
	type TransferLifecycleAudit,
} from '$lib/native/testing/backgroundWorkHarness';
import { withCriticalScope, type CriticalScopeHandle } from './criticalScope';
import type { RangeObservation, TransferExecutorOutcome } from './transferExecutor';

const SHA_OK = 'ab'.repeat(32);
const SHA_OTHER = 'cd'.repeat(32);
const SHA_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const DEADLINE = '2026-09-24T00:00:00Z';

function start(overrides: {
	accountId?: string;
	jobId?: string;
	blobId?: string;
	expectedSize?: number;
	expectedSha256?: string;
	deadlineUtc?: string;
} = {}) {
	return {
		accountId: 'acct-1',
		jobId: 'job-t1',
		blobId: SHA_OK,
		expectedSize: 10,
		expectedSha256: SHA_OK,
		deadlineUtc: DEADLINE,
		...overrides,
	};
}

function range206(bodyBytes: number, opts: { start?: number; mintGeneration?: number; mintWasCurrent?: boolean } = {}): RangeObservation {
	const requestStart = opts.start ?? 0;
	const end = requestStart + bodyBytes - 1;
	return {
		status: 206,
		etag: `"${SHA_OK}"`,
		contentRange: `bytes ${requestStart}-${end}/10`,
		contentEncoding: 'identity',
		bodyByteCount: bodyBytes,
		bodyBytes: new Uint8Array(bodyBytes).fill(1),
		mintGeneration: opts.mintGeneration ?? 1,
		mintWasCurrent: opts.mintWasCurrent ?? true,
	};
}

function range404(opts: { mintGeneration?: number; mintWasCurrent?: boolean; authenticatedResult?: boolean } = {}): RangeObservation {
	return {
		status: 404,
		bodyByteCount: 0,
		mintGeneration: opts.mintGeneration ?? 1,
		mintWasCurrent: opts.mintWasCurrent ?? true,
		...(opts.authenticatedResult === undefined ? {} : { authenticatedResult: opts.authenticatedResult }),
	};
}

/** A valid persisted row, as the durable transfer store would hold it. */
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
		deadlineUtc: DEADLINE,
		attempts: 1,
		...overrides,
	};
}

/** Real observations, accumulated by the scenarios below. The mutable mirror
 * feeds the auditor (whose readonly inputs accept these arrays) in afterAll. */
const observations = {
	outcomes: [] as TransferExecutorOutcome[],
	persistedTexts: [] as string[],
	redirectRejectedWithoutFollow: false,
	restartRemintedUnderCurrentAuthorization: false,
	accountChangePurgedWithoutReuse: false,
	revocationCleanupPausedAdmission: false,
	confirmedPurgedHiddenPreservedStaleIgnored: false,
	criticalScopesBalanced: false,
};

/** E4-I Astra correction (finding 14): every scenario's ACTUAL verdict gates
 * the retained receipt. */
const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

function recordOutcome(executor: HarnessExecutor, outcome: TransferExecutorOutcome): TransferExecutorOutcome {
	observations.outcomes.push(outcome);
	observations.persistedTexts.push(JSON.stringify(executor.persisted.snapshot()));
	return outcome;
}

async function runLifecycle(): Promise<{ audit: TransferLifecycleAudit }> {
	const executor = createHarnessExecutor({
		responses: [range206(10)],
		digest: SHA_OK,
	});
	const promoted = await executor.startTransfer(start());
	expect(promoted.kind).toBe('promoted');
	recordOutcome(executor, promoted);

	// Restart path: a completed transfer reloads from persistence; a fresh
	// cycle mints NO new token and sends NO new request (verified success is
	// replayed) — observed through the recording ports, never asserted into
	// existence.
	const mintsBefore = executor.mints.length;
	const fetchesBefore = executor.fetches.length;
	const restarted = await executor.runTransfer('job-t1');
	expect(restarted.kind).toBe('promoted');
	recordOutcome(executor, restarted);
	const restartReminted = executor.mints.length === mintsBefore
		&& executor.fetches.length === fetchesBefore;
	return { audit: { ...observations, restartRemintedUnderCurrentAuthorization: restartReminted } };
}

describe('CAS-E4I-TRANSFER-LIFECYCLE', () => {
	it('positive oracle: 206 ranges write the sink, promote after exact hash, and persist no bearer/URL', async () => {
		const { audit } = await runLifecycle();
		// The restart oracle is fed from the recording ports.
		observations.restartRemintedUnderCurrentAuthorization = audit.restartRemintedUnderCurrentAuthorization;
		// Scenario facts are asserted directly here; the FULL case audit (over
		// every scenario's real observation) runs once in afterAll, after all
		// required scenarios have finished.
		expect(observations.outcomes.map((outcome) => outcome.kind)).toEqual(['promoted', 'promoted']);
		expect(observations.persistedTexts.join('\n')).not.toMatch(/bearer|authorization:|https?:\/\//i);
	});

	it('wiring: accepted ranges write acknowledged bytes, verification promotes, completion persists', async () => {
		const executor = createHarnessExecutor({ responses: [range206(10)], digest: SHA_OK });
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('promoted');
		recordOutcome(executor, outcome);
		expect(executor.sink.writes).toEqual([{ offset: 0, length: 10 }]);
		expect(executor.sink.promotes).toBe(1);
		expect(executor.persisted.snapshot().at(-1)).toMatchObject({ state: 'complete', committedBytes: 10 });
		// The persisted rows carry identity and bytes metadata only.
		const serialized = JSON.stringify(executor.persisted.snapshot());
		expect(serialized).not.toMatch(/bearer|https?:\/\//i);
	});

	it('redirects are rejected and never followed, and the partial purges', async () => {
		const executor = createHarnessExecutor({
			responses: [{
				status: 302,
				bodyByteCount: 0,
				mintGeneration: 1,
				mintWasCurrent: true,
			}],
		});
		const outcome = await executor.startTransfer(start());
		expect(outcome).toMatchObject({ kind: 'safe-restart', reason: 'redirect-rejected', purged: true });
		recordOutcome(executor, outcome);
		// Exactly one fetch: the redirect target was never requested.
		const singleFetch = executor.fetches.length === 1;
		const purged = executor.sink.purges === 1 && executor.persisted.snapshot().length === 0;
		observations.redirectRejectedWithoutFollow = singleFetch && purged;
		// The safe-restart carries the retained job envelope.
		expect(outcome).toMatchObject({ deadlineUtc: DEADLINE, attempts: 0 });
		expect(singleFetch && purged).toBe(true);
	});

	it('restart remints under current authorization; the old bearer is never retained', async () => {
		const executor = createHarnessExecutor({
			responses: [
				{ status: 401, bodyByteCount: 0, mintGeneration: 1, mintWasCurrent: true },
				range206(5, { start: 0, mintGeneration: 2 }),
			],
		});
		const first = await executor.startTransfer(start());
		expect(first.kind).toBe('reauthorize');
		recordOutcome(executor, first);
		expect(executor.mints).toHaveLength(1);
		// Authorization rotates; the next cycle remints under generation 2 and
		// verified bytes are preserved (range continues from the checkpoint).
		executor.setAuthorization({ accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 2 });
		const second = await executor.runTransfer('job-t1');
		expect(second.kind === 'retry' || second.kind === 'promoted').toBe(true);
		recordOutcome(executor, second);
		expect(executor.mints).toHaveLength(2);
		expect(executor.mints[1].generation).toBe(2);
		observations.restartRemintedUnderCurrentAuthorization = true;
	});

	it('a revoke racing a PENDING mint cannot resurrect into fetch/write/promote/persist', async () => {
		// Astra finding 10 reproduction: pending mint → revoke → resolve mint →
		// the old code ran the fetch, wrote, promoted and persisted revoked work.
		const holder: { executor?: HarnessExecutor } = {};
		const executor = createHarnessExecutor({
			responses: [range206(10)],
			digest: SHA_OK,
			onMint: () => {
				// Revocation lands while the mint is still pending.
				holder.executor!.setAuthorization(null);
			},
		});
		holder.executor = executor;
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('paused-admission');
		recordOutcome(executor, outcome);
		// NO effect escaped the revoked authorization: nothing was fetched,
		// written or promoted, and no COMPLETED state was ever recorded. The
		// initial account-bound checkpoint row may persist (it is valid durable
		// state for a later authorized cycle) but holds zero verified bytes.
		expect(executor.fetches).toHaveLength(0);
		expect(executor.sink.writes).toHaveLength(0);
		expect(executor.sink.promotes).toBe(0);
		const rows = executor.persisted.snapshot();
		expect(rows.every((row) => row.state !== 'complete' && row.committedBytes === 0)).toBe(true);
	});

	it('Critical beginning mid-flight aborts the transfer before any effect', async () => {
		let securityHandle: CriticalScopeHandle | null = null;
		const executor = createHarnessExecutor({
			responses: [range206(10)],
			digest: SHA_OK,
			onFetch: () => {
				// Security work begins while the range request is in flight.
				securityHandle = executor.critical.begin('security');
			},
		});
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		recordOutcome(executor, outcome);
		expect(executor.sink.writes).toHaveLength(0);
		expect(executor.sink.promotes).toBe(0);
		// The scope ends balanced: the counter returns to zero.
		securityHandle!.end();
		expect(executor.critical.isActive()).toBe(false);
		observations.criticalScopesBalanced = true;
	});

	it('account change cancels and purges with zero cross-account reuse', async () => {
		const executor = createHarnessExecutor({ responses: [range206(5)] });
		const first = await executor.startTransfer(start());
		expect(first.kind).toBe('retry');
		recordOutcome(executor, first);
		expect(executor.persisted.snapshot()).toHaveLength(1);
		await executor.cancelTransfer('job-t1', 'account-change');
		expect(executor.persisted.snapshot()).toHaveLength(0);
		expect(executor.sink.purges).toBe(1);
		// A different account cannot adopt the purged transfer: the checkpoint
		// row is gone, so re-entry is a safe restart without any state reuse.
		executor.setAuthorization({ accountId: 'acct-2', deviceId: 'dev-9', policyGeneration: 3 });
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind === 'safe-restart' || outcome.kind === 'disposed' || outcome.kind === 'paused-admission').toBe(true);
		recordOutcome(executor, outcome);
		observations.accountChangePurgedWithoutReuse = true;
	});

	it('a completed checkpoint of account A never replays for account B (terminal paths validate identity)', async () => {
		// Astra finding 11 reproduction: the completed-checkpoint replay returned
		// A's promoted checkpoint before any account validation.
		const executor = createHarnessExecutor({ authorization: { accountId: 'acct-B', deviceId: 'dev-2', policyGeneration: 1 } });
		await executor.persisted.upsertCheckpoint(persistedRow({ state: 'complete' }));
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).not.toBe('promoted');
		expect(outcome.kind).toBe('paused-admission');
		recordOutcome(executor, outcome);
		// The mis-accounted row was purged through the existing path.
		expect(executor.persisted.snapshot()).toHaveLength(0);
		observations.accountChangePurgedWithoutReuse = true;
	});

	it('the zero-length completion validates account identity before promoting', async () => {
		// Astra finding 11 (zero-length path): the terminal-empty result used to
		// bypass the account check.
		const executor = createHarnessExecutor({ authorization: { accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 1 } });
		const outcome = await executor.startTransfer({
			accountId: 'acct-OTHER',
			jobId: 'job-t1',
			blobId: SHA_EMPTY,
			expectedSize: 0,
			expectedSha256: SHA_EMPTY,
			deadlineUtc: DEADLINE,
		});
		expect(outcome.kind).not.toBe('promoted');
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'authExpired' });
	});

	it('revocation cleanup drops the bearer and pauses admission without claiming deletion', async () => {
		const executor = createHarnessExecutor({ authorization: null });
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'authExpired' });
		recordOutcome(executor, outcome);
		expect(executor.mints).toHaveLength(0);
		expect(executor.fetches).toHaveLength(0);
		observations.revocationCleanupPausedAdmission = true;
	});

	it('confirmed content-unavailable purges; RAW 404 preserves; hidden preserves; stale ignored', async () => {
		// Astra finding 12 reproduction: a raw 404 with a CURRENT mint used to
		// purge valid partial state — mint facts are not authorization.
		const raw = createHarnessExecutor({
			responses: [range404({ mintGeneration: 1, mintWasCurrent: true })],
		});
		const rawOutcome = await raw.startTransfer(start());
		expect(rawOutcome).toEqual({ kind: 'paused-admission', reason: 'authExpired' });
		recordOutcome(raw, rawOutcome);
		// The valid partial state SURVIVED the raw 404.
		expect(raw.persisted.snapshot()).toHaveLength(1);
		expect(raw.sink.purges).toBe(0);

		// Confirmed: an AUTHENTICATED current-authorized result is terminal-
		// unavailable + purge.
		const confirmed = createHarnessExecutor({
			responses: [range404({ mintGeneration: 1, mintWasCurrent: true, authenticatedResult: true })],
		});
		const confirmedOutcome = await confirmed.startTransfer(start());
		expect(confirmedOutcome).toMatchObject({ kind: 'terminal-unavailable', purged: true });
		recordOutcome(confirmed, confirmedOutcome);
		expect(confirmed.persisted.snapshot()).toHaveLength(0);

		// Hidden/ambiguous: the mint was not provably current — valid encrypted
		// state is preserved and admission pauses.
		const hidden = createHarnessExecutor({
			responses: [range404({ mintGeneration: 1, mintWasCurrent: false })],
		});
		const hiddenOutcome = await hidden.startTransfer(start());
		expect(hiddenOutcome).toMatchObject({ kind: 'stale-result' });
		recordOutcome(hidden, hiddenOutcome);
		expect(hidden.persisted.snapshot()).toHaveLength(1);

		// Stale generation: a world change between mint and observation is
		// ignored without any purge; the next cycle remints fresh.
		const stale = createHarnessExecutor({
			responses: [range404({ mintGeneration: 1, mintWasCurrent: true })],
		});
		stale.setAuthorization({ accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 2 });
		const staleOutcome = await stale.startTransfer(start());
		expect(staleOutcome).toMatchObject({ kind: 'stale-result' });
		recordOutcome(stale, staleOutcome);
		expect(stale.persisted.snapshot()).toHaveLength(1);

		observations.confirmedPurgedHiddenPreservedStaleIgnored = rawOutcome.kind === 'paused-admission'
			&& confirmedOutcome.kind === 'terminal-unavailable'
			&& hiddenOutcome.kind === 'stale-result'
			&& staleOutcome.kind === 'stale-result';
	});

	it('a revoke racing the sink WRITE cannot resurrect into persist/promote (r2)', async () => {
		// Astra r2 finding 4 reproduction: cancellation ownership was released
		// right after the fetch, so a revoke during openPartial purged while the
		// cycle continued write → promote → persist complete.
		const holder: { executor?: HarnessExecutor } = {};
		const executor = createHarnessExecutor({
			responses: [range206(10)],
			digest: SHA_OK,
			onOpenPartial: async () => {
				// The revocation lands while the sink write effect is in flight:
				// cancelTransfer aborts the cycle AND purges account-scoped state.
				await holder.executor!.cancelTransfer('job-t1', 'revoked');
			},
		});
		holder.executor = executor;
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('paused-admission');
		recordOutcome(executor, outcome);
		// Nothing was resurrected after the purge: no promote, no completed
		// state, and the write never landed.
		expect(executor.sink.promotes).toBe(0);
		expect(executor.sink.writes).toHaveLength(0);
		expect(executor.persisted.snapshot().every((row) => row.state !== 'complete')).toBe(true);
	});

	it('a revoke racing the verification digest cannot promote (restart path, r2)', async () => {
		// Astra r2 finding 4, second half: the verification-restart path ran its
		// digest OUTSIDE the controller registration, so a revoke during the
		// digest await promoted + persisted a completion the revoke had purged.
		const holder: { executor?: HarnessExecutor } = {};
		const executor = createHarnessExecutor({
			digest: SHA_OK,
			onDigest: async () => {
				await holder.executor!.cancelTransfer('job-t1', 'revoked');
			},
		});
		holder.executor = executor;
		await executor.persisted.upsertCheckpoint(persistedRow({ state: 'verifying', committedBytes: 10 }));
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('paused-admission');
		recordOutcome(executor, outcome);
		expect(executor.sink.promotes).toBe(0);
		expect(executor.persisted.snapshot().every((row) => row.state !== 'complete')).toBe(true);
	});

	it('a revoke racing the promote cannot recreate a completed checkpoint (r5)', async () => {
		// Astra r5 finding 1 reproduction: the completion persist followed the
		// awaited promote with no new interruption check, so a revoke landing in
		// that window purged (cancelTransfer's account-scoped purge) while the
		// cycle still persisted a completed checkpoint over the purge.
		const holder: { executor?: HarnessExecutor } = {};
		const executor = createHarnessExecutor({
			responses: [range206(10)],
			digest: SHA_OK,
			onPromote: async () => {
				// The revocation lands while promote is in flight: the controller
				// aborts and the account-scoped purge runs concurrently.
				await holder.executor!.cancelTransfer('job-t1', 'revoked');
			},
		});
		holder.executor = executor;
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('paused-admission');
		recordOutcome(executor, outcome);
		// No completed state was ever persisted behind the revoke: the purged
		// checkpoint was not resurrected.
		expect(executor.persisted.snapshot().every((row) => row.state !== 'complete')).toBe(true);
		expect(executor.persisted.snapshot()).toHaveLength(0);
	});

	it('a revoke racing the restart-path promote cannot recreate a completed checkpoint (r5)', async () => {
		// Same window on the verification-restart path: a persisted `verifying`
		// transfer promotes after its digest; the revoke's purge lands during
		// the awaited promote and the completion persist must not follow it.
		const holder: { executor?: HarnessExecutor } = {};
		const executor = createHarnessExecutor({
			digest: SHA_OK,
			onPromote: async () => {
				await holder.executor!.cancelTransfer('job-t1', 'revoked');
			},
		});
		holder.executor = executor;
		await executor.persisted.upsertCheckpoint(persistedRow({ state: 'verifying', committedBytes: 10 }));
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('paused-admission');
		recordOutcome(executor, outcome);
		expect(executor.persisted.snapshot().every((row) => row.state !== 'complete')).toBe(true);
		expect(executor.persisted.snapshot()).toHaveLength(0);
	});

	it('a fresh start past its deadline expires instead of completing (r2)', async () => {
		// Astra r2 finding 11a: the expiry check covered loaded checkpoints only.
		const executor = createHarnessExecutor({ responses: [range206(10)], digest: SHA_OK });
		const outcome = await executor.startTransfer(start({ deadlineUtc: '2026-09-01T00:00:00Z' }));
		expect(outcome.kind).toBe('terminal-expired');
		recordOutcome(executor, outcome);
		expect(executor.fetches).toHaveLength(0);
		expect(executor.sink.promotes).toBe(0);
		expect(executor.persisted.snapshot().every((row) => row.state === 'expired')).toBe(true);
	});

	it('a deadline crossed during the fetch never promotes (r2)', async () => {
		// Astra r2 finding 11b: the deadline raced the in-flight range request
		// and the response still wrote, promoted and persisted.
		let mutableNow = Date.parse('2026-09-17T01:00:00Z');
		const executor = createHarnessExecutor({
			responses: [range206(10)],
			digest: SHA_OK,
			onFetch: () => {
				// The deadline crosses while the range request is in flight.
				mutableNow = Date.parse('2026-09-25T00:00:00Z');
			},
			nowUtc: () => new Date(mutableNow).toISOString(),
		});
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('terminal-expired');
		recordOutcome(executor, outcome);
		expect(executor.sink.writes).toHaveLength(0);
		expect(executor.sink.promotes).toBe(0);
		expect(executor.persisted.snapshot().every((row) => row.state === 'expired')).toBe(true);
	});

	it('a deadline crossed during verification never promotes (r2)', async () => {
		// Astra r2 finding 11c: the deadline crossed during the digest await and
		// the transfer still promoted.
		let mutableNow = Date.parse('2026-09-17T01:00:00Z');
		const executor = createHarnessExecutor({
			responses: [range206(10)],
			digest: SHA_OK,
			onDigest: () => {
				mutableNow = Date.parse('2026-09-25T00:00:00Z');
			},
			nowUtc: () => new Date(mutableNow).toISOString(),
		});
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('terminal-expired');
		recordOutcome(executor, outcome);
		expect(executor.sink.promotes).toBe(0);
		expect(executor.persisted.snapshot().every((row) => row.state === 'expired')).toBe(true);
	});

	it('a deadline crossed during the promote never persists a completion (r6, accepted path)', async () => {
		// Astra r6 finding 1 reproduction: the post-promote critical section
		// re-verified only `interrupted()` — an expiry crossing during the
		// awaited promote still persisted the completed checkpoint.
		let mutableNow = Date.parse('2026-09-17T01:00:00Z');
		const executor = createHarnessExecutor({
			responses: [range206(10)],
			digest: SHA_OK,
			onPromote: () => {
				// The retained deadline crosses while promote is in flight.
				mutableNow = Date.parse('2026-09-25T00:00:00Z');
			},
			nowUtc: () => new Date(mutableNow).toISOString(),
		});
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('terminal-expired');
		recordOutcome(executor, outcome);
		// The completion was NEVER persisted: the row is the expired terminal
		// shape with its retained envelope, not a completion past the deadline.
		expect(executor.persisted.snapshot().every((row) => row.state === 'expired')).toBe(true);
		expect(executor.persisted.snapshot().every((row) => row.state !== 'complete')).toBe(true);
		expect(executor.persisted.snapshot().at(-1)).toMatchObject({ deadlineUtc: DEADLINE, committedBytes: 10 });
	});

	it('a deadline crossed during the restart-path promote never persists a completion (r6)', async () => {
		// Same post-promote window on the verification-restart path: the
		// persisted `verifying` transfer promotes after its digest and the
		// expiry crossing that window must expire, never re-persist complete.
		let mutableNow = Date.parse('2026-09-17T01:00:00Z');
		const executor = createHarnessExecutor({
			digest: SHA_OK,
			onPromote: () => {
				mutableNow = Date.parse('2026-09-25T00:00:00Z');
			},
			nowUtc: () => new Date(mutableNow).toISOString(),
		});
		await executor.persisted.upsertCheckpoint(persistedRow({ state: 'verifying', committedBytes: 10 }));
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('terminal-expired');
		recordOutcome(executor, outcome);
		expect(executor.persisted.snapshot().every((row) => row.state === 'expired')).toBe(true);
		expect(executor.persisted.snapshot().every((row) => row.state !== 'complete')).toBe(true);
		// No network effect ran on the restart path.
		expect(executor.fetches).toHaveLength(0);
	});

	it('a raw 404 stays recoverable: no failed row is persisted and recovery remints (r2)', async () => {
		// Astra r2 finding 12 reproduction: the unproven 404 persisted a `failed`
		// checkpoint while reporting paused-admission; the terminal replay then
		// answered already-failed forever and recovery could not remint.
		const executor = createHarnessExecutor({
			responses: [
				range404({ mintGeneration: 1, mintWasCurrent: true }),
				range206(10, { mintGeneration: 2 }),
			],
			digest: SHA_OK,
		});
		const first = await executor.startTransfer(start());
		expect(first).toEqual({ kind: 'paused-admission', reason: 'authExpired' });
		recordOutcome(executor, first);
		// The checkpoint row kept its resumable state — NOT `failed`.
		const row = executor.persisted.snapshot().at(-1);
		expect(row?.state).not.toBe('failed');
		// A later authorized admission REMINTS and completes the transfer.
		executor.setAuthorization({ accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 2 });
		const second = await executor.runTransfer('job-t1');
		expect(second.kind).toBe('promoted');
		recordOutcome(executor, second);
		expect(executor.mints).toHaveLength(2);
		expect(executor.sink.promotes).toBe(1);
	});

	it('a fully downloaded verifying transfer verifies WITHOUT any network effect', async () => {
		// Astra finding 15a reproduction: restart re-requested a range for the
		// complete transfer (EOF → 416 → purge of a fully downloaded transfer).
		const executor = createHarnessExecutor({ digest: SHA_OK });
		await executor.persisted.upsertCheckpoint(persistedRow({ state: 'verifying', committedBytes: 10 }));
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('promoted');
		recordOutcome(executor, outcome);
		expect(executor.fetches).toHaveLength(0);
		expect(executor.mints).toHaveLength(0);
		expect(executor.sink.purges).toBe(0);
		expect(executor.sink.promotes).toBe(1);
	});

	it('an expired checkpoint expires WITHOUT downloading', async () => {
		// Astra finding 15b reproduction: an expired checkpoint could still
		// download and become complete.
		const executor = createHarnessExecutor({ responses: [range206(5, { start: 5 })] });
		await executor.persisted.upsertCheckpoint(persistedRow({
			state: 'transferring',
			committedBytes: 5,
			deadlineUtc: '2026-09-01T00:00:00Z',
		}));
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('terminal-expired');
		recordOutcome(executor, outcome);
		expect(executor.fetches).toHaveLength(0);
		expect(executor.mints).toHaveLength(0);
		expect((outcome as { checkpoint: { attempts: number } }).checkpoint.attempts).toBe(1);
	});

	it('a fetch exception is an E3 transport retry carrying the retained envelope', async () => {
		// Astra finding 16 reproduction: every fetch exception was classified
		// authExpired — no retry, attempts stuck at zero.
		const executor = createHarnessExecutor({ responses: [] });
		const outcome = await executor.startTransfer(start());
		expect(outcome.kind).toBe('retry');
		recordOutcome(executor, outcome);
		const persisted = executor.persisted.snapshot().at(-1);
		expect(persisted).toMatchObject({ state: 'retry', attempts: 1 });
		// The deadline envelope is retained in the persisted checkpoint.
		expect(persisted?.deadlineUtc).toBe(DEADLINE);
	});

	it('an expired transfer with a transport failure terminates as expired, never as auth-expiry', async () => {
		const executor = createHarnessExecutor({
			responses: [],
		});
		await executor.persisted.upsertCheckpoint(persistedRow({
			state: 'transferring',
			committedBytes: 5,
			deadlineUtc: '2026-09-01T00:00:00Z',
		}));
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome.kind).toBe('terminal-expired');
		recordOutcome(executor, outcome);
		expect(executor.fetches).toHaveLength(0);
	});

	it('unmount/re-entry: a disposed executor reports disposed and stops minting', async () => {
		const executor = createHarnessExecutor({ responses: [range206(10)], digest: SHA_OK });
		expect(executor.disposed).toBe(false);
		executor.dispose();
		expect(executor.disposed).toBe(true);
		const outcome = await executor.runTransfer('job-t1');
		expect(outcome).toEqual({ kind: 'disposed' });
	});

	it('Critical security work suppresses optional transfer I/O; scopes stay balanced under failure', async () => {
		const executor = createHarnessExecutor({ responses: [] });
		const handle = executor.critical.begin('security');
		const outcome = await executor.startTransfer(start());
		expect(outcome).toEqual({ kind: 'paused-admission', reason: 'criticalActivity' });
		recordOutcome(executor, outcome);
		expect(executor.mints).toHaveLength(0);
		// Balanced under a throwing body: the counter must return to zero.
		await expect(withCriticalScope(executor.critical, async () => {
			throw new Error('security work failed');
		})).rejects.toThrow('security work failed');
		handle.end();
		expect(executor.critical.count()).toBe(0);
		expect(executor.critical.isActive()).toBe(false);
		observations.criticalScopesBalanced = true;
	});

	it('hash mismatch discards the unsafe partial (safe restart, purge)', async () => {
		const executor = createHarnessExecutor({ responses: [range206(10)], digest: SHA_OTHER });
		const outcome = await executor.startTransfer(start());
		expect(outcome).toMatchObject({ kind: 'safe-restart', reason: 'hash-mismatch', purged: true });
		recordOutcome(executor, outcome);
		expect(executor.persisted.snapshot()).toHaveLength(0);
		// The safe-restart retains the job envelope (Astra finding 16).
		expect(outcome).toMatchObject({ deadlineUtc: DEADLINE, attempts: 0 });
	});

	it('planted faults produce the pinned FAIL text with distinct finite causes', async () => {
		const pinned = e4iFailure('CAS-E4I-TRANSFER-LIFECYCLE', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E4I-TRANSFER-LIFECYCLE: transfer lifecycle escaped current authorization or retained a prohibited bearer',
		);
		const leaked = auditTransferLifecycle({
			outcomes: [{ kind: 'promoted' }],
			persistedTexts: ['{"jobId":"job-t1","bearer":"bearer-1-1"}'],
			redirectRejectedWithoutFollow: true,
			restartRemintedUnderCurrentAuthorization: true,
			accountChangePurgedWithoutReuse: true,
			revocationCleanupPausedAdmission: true,
			confirmedPurgedHiddenPreservedStaleIgnored: true,
			criticalScopesBalanced: true,
		});
		expect(leaked.ok).toBe(false);
		expect(leaked.fail).toBe(pinned.fail);
		expect(leaked.cause).toBe('subOracleId=prohibited-bearer-or-url-retained lane=core');

		const followed = auditTransferLifecycle({
			outcomes: [{ kind: 'promoted' }],
			persistedTexts: ['{"jobId":"job-t1"}'],
			redirectRejectedWithoutFollow: false,
			restartRemintedUnderCurrentAuthorization: true,
			accountChangePurgedWithoutReuse: true,
			revocationCleanupPausedAdmission: true,
			confirmedPurgedHiddenPreservedStaleIgnored: true,
			criticalScopesBalanced: true,
		});
		expect(followed.cause).toBe('subOracleId=redirect-followed lane=core');
		expect(followed.cause).not.toBe(leaked.cause);
	});
});

// The receipt is written ONCE, after every required scenario finished, from
// the REAL accumulated observations (Astra finding 19) AND gated on every
// scenario's actual verdict (Astra finding 14, r2).
afterAll(async () => {
	const verdict = auditTransferLifecycle(observations);
	const final = gateVerdictOnScenarios(verdict, scenarioFailures);
	expect(final.ok, JSON.stringify({ final, observations })).toBe(true);
	writeCaseResult(final);
});
