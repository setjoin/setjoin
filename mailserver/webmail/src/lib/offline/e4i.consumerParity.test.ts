/**
 * CAS-E4I-CONSUMER-PARITY — E4-I verification binding (core lane).
 *
 * E4 capability-specific execution and E5 projections consume the SAME
 * committed/unknown/paused results; no surface invents a completion. Both
 * consumers read one source (`Coordinator.readJobResult` over the job store),
 * and the E5 mapping (`schedulerStateFromJobResult`) is the only projection.
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';

import {
	auditConsumerParity,
	createHarnessCoordinator,
	e4iFailure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
	type ConsumerParityPair,
} from '$lib/native/testing/backgroundWorkHarness';
import { schedulerStateFromJobResult } from './statusProjection';

/** E4-I Astra correction (finding 14): every scenario's ACTUAL verdict gates
 * the retained receipt, and the receipt is written ONCE in afterAll — never
 * from inside the first test, where later required scenarios cannot have
 * invalidated it yet. */
const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

/** The positive oracle's consumed pairs: the afterAll re-audits the SAME real
 * observations when the receipt is written (never inside a mid-suite test). */
let accumulatedPairs: ConsumerParityPair[] = [];

describe('CAS-E4I-CONSUMER-PARITY', () => {
	it('positive oracle: one committed result sequence drives identical E4/E5 consumption', async () => {
		const events: import('./coordinator').CoordinatorEvent[] = [];

		// Committed complete: the walk finishes and only the committed record
		// lets any consumer observe completion.
		const completed = createHarnessCoordinator({
			events,
			pages: [{
				newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [],
				emails: [{
					id: '1', threadId: 't', mailboxIds: { Inbox: true }, keywords: { $seen: true },
					receivedAt: '2026-09-01T00:00:00Z', hasAttachment: false, preview: '', subject: '',
				} as never],
			}],
		});
		await completed.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await completed.runDueWork();
		const completeRead = await completed.readJobResult('opt-reconnect-acct-1');
		expect(completeRead.kind).toBe('committed');

		// Committed paused: a stale capability snapshot cannot authorize work;
		// the recorded pause keeps its exact reason for both consumers.
		const paused = createHarnessCoordinator({ observationAgeMs: 6_000 });
		await paused.ingestTrigger({ kind: 'reconnect', accountId: 'acct-2', generation: 1 });
		await paused.runDueWork();
		const pausedRead = await paused.readJobResult('opt-reconnect-acct-2');
		expect(pausedRead.kind).toBe('committed');
		expect(pausedRead.kind === 'committed' && pausedRead.result.state === 'paused').toBe(true);

		// Unknown: a job nobody committed anything for.
		const unknown = await completed.readJobResult('opt-never-ran');

		const pairs: ConsumerParityPair[] = [];
		for (const read of [completeRead, pausedRead, unknown]) {
			if (read.kind === 'committed') {
				pairs.push({
					readKind: 'committed',
					resultState: read.result.state,
					pauseReason: read.result.state === 'paused' ? read.result.reason : undefined,
					projected: schedulerStateFromJobResult(read.result),
				});
			} else {
				pairs.push({ readKind: 'unknown', projected: schedulerStateFromJobResult(null) });
			}
		}
		const verdict = auditConsumerParity(pairs);
		expect(verdict.ok, JSON.stringify(verdict)).toBe(true);
		// The unknown result must be idle — never an invented completion.
		expect(pairs[2].projected).toEqual({ kind: 'idle' });
		accumulatedPairs = pairs;
	});

	it('paused reasons survive the shared mapping unchanged', async () => {
		const paused = createHarnessCoordinator({ observationAgeMs: 6_000 });
		await paused.ingestTrigger({ kind: 'reconnect', accountId: 'acct-9', generation: 1 });
		await paused.runDueWork();
		const read = await paused.readJobResult('opt-reconnect-acct-9');
		expect(read.kind).toBe('committed');
		if (read.kind === 'committed' && read.result.state === 'paused') {
			const mapped = schedulerStateFromJobResult(read.result);
			expect(mapped).toEqual({ kind: 'paused', reason: read.result.reason });
			// Stale signal freshness maps to capabilityUnavailable, not a
			// fabricated network/policy claim.
			expect(read.result.reason).toBe('capabilityUnavailable');
		} else {
			throw new Error('expected a committed paused result');
		}
	});

	it('planted faults produce the pinned FAIL text with distinct finite causes', () => {
		const pinned = e4iFailure('CAS-E4I-CONSUMER-PARITY', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E4I-CONSUMER-PARITY: consumer projection disagreed with the committed execution result',
		);
		const invented = auditConsumerParity([
			{ readKind: 'unknown', projected: { kind: 'running' } },
		]);
		expect(invented.ok).toBe(false);
		expect(invented.fail).toBe(pinned.fail);
		expect(invented.cause).toBe('subOracleId=unknown-invented-state-0 lane=core');

		const disagreement = auditConsumerParity([
			{ readKind: 'committed', resultState: 'complete', projected: { kind: 'paused', reason: 'policyDenied' } },
			{ readKind: 'committed', resultState: 'paused', pauseReason: 'meteredNetwork', projected: { kind: 'idle' } },
		]);
		expect(disagreement.ok).toBe(false);
		expect(disagreement.fail).toBe(pinned.fail);
		expect(disagreement.cause).toBe('subOracleId=projection-disagreement-0 lane=core');
		expect(disagreement.cause).not.toBe(invented.cause);

		const empty = auditConsumerParity([]);
		expect(empty.cause).toBe('subOracleId=positive-oracle-missing lane=core');
	});

	// The receipt is written ONCE, after every required scenario finished, from
	// the re-audited positive oracle AND gated on every scenario's actual
	// verdict (Astra finding 14, r2: the old receipt reported PASS from inside
	// the FIRST test, before the later required scenarios ran).
	afterAll(async () => {
		const verdict = auditConsumerParity(accumulatedPairs);
		const final = gateVerdictOnScenarios(verdict, scenarioFailures);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});
