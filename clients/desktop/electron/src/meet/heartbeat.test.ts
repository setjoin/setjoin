import { describe, expect, it } from 'vitest';

import {
	CRASH_MARKER_SCHEMA,
	HEARTBEAT_INTERVAL_MS,
	HEARTBEAT_SCHEMA,
	HeartbeatMonitor,
	MAX_MISSED_HEARTBEATS,
	STOP_CONDITION_PRIORITY,
	evaluateStopConditions,
	encodeCrashMarker,
	parseCrashMarker,
} from './heartbeat';

function monitor(overrides: Partial<ConstructorParameters<typeof HeartbeatMonitor>[0]> = {}) {
	return new HeartbeatMonitor(
		{
			intervalMs: HEARTBEAT_INTERVAL_MS,
			maxMissed: MAX_MISSED_HEARTBEATS,
			meetingId: 42,
			recordingId: 7,
			leaseGeneration: 3,
			surfaces: ['microphone'],
			producerVersion: 'electron-43+chromium-143',
			...overrides,
		},
		'execute',
	);
}

describe('CaptureHeartbeat frames', () => {
	it('builds the typed frame with monotonic seq and honest nulls', () => {
		const m = monitor();
		const first = m.recordSent(1_000, 5 * 1024 ** 3);
		expect(first).toMatchObject({
			schema: HEARTBEAT_SCHEMA,
			meetingId: 42,
			recordingId: 7,
			leaseGeneration: 3,
			seq: 1,
			sentAtUnixMs: 1_000,
			captureState: 'capturing',
			diskFreeBytes: 5 * 1024 ** 3,
			surfaces: ['microphone'],
			producerVersion: 'electron-43+chromium-143',
		});
		const second = m.recordSent(11_000, null);
		expect(second.seq).toBe(2);
		expect(second.diskFreeBytes).toBeNull(); // probe failure is reported, never fabricated
	});

	it('never fabricates frames for missed slots: a gap IS the report', () => {
		const m = monitor();
		m.recordSent(0, null);
		// 35s of silence evaluated at 40s: the next frame sent carries seq 2,
		// not three backfilled frames for the missed slots.
		expect(m.evaluate(HEARTBEAT_INTERVAL_MS * 4)).toMatchObject({ stalled: true });
		const frame = m.recordSent(HEARTBEAT_INTERVAL_MS * 4 + 1, null);
		expect(frame.seq).toBe(2);
		expect(m.missedCount).toBe(0); // recordSent resets the stall counter
	});

	it('carries the final stopped state on the stop frame', () => {
		const m = monitor();
		m.recordSent(0, null);
		const stop = m.recordStopped(5_000, null);
		expect(stop.captureState).toBe('stopped');
		expect(stop.seq).toBe(2);
	});
});

describe('HeartbeatMonitor cadence + stall', () => {
	it('is inert unless the rollout admits capture', () => {
		expect(
			() =>
				new HeartbeatMonitor(
					{
						intervalMs: HEARTBEAT_INTERVAL_MS,
						maxMissed: MAX_MISSED_HEARTBEATS,
						meetingId: 42,
						recordingId: null,
						leaseGeneration: null,
						surfaces: ['microphone'],
						producerVersion: 'x',
					},
					'off',
				),
		).toThrowError(/'execute' rollout mode/);
	});

	it('is due immediately when nothing was ever sent', () => {
		expect(monitor().evaluate(0)).toEqual({ dueNow: true, missedCount: 0, stalled: false });
	});

	it('becomes due at the interval and stalls after the missed budget', () => {
		const m = monitor();
		m.recordSent(0, null);
		expect(m.evaluate(HEARTBEAT_INTERVAL_MS - 1)).toEqual({ dueNow: false, missedCount: 0, stalled: false });
		expect(m.evaluate(HEARTBEAT_INTERVAL_MS)).toEqual({ dueNow: true, missedCount: 0, stalled: false });

		// 3 full intervals of silence beyond the due slot = MAX_MISSED_HEARTBEATS → stalled.
		const stalledAt = HEARTBEAT_INTERVAL_MS * (MAX_MISSED_HEARTBEATS + 1);
		expect(m.evaluate(stalledAt - 1)).toMatchObject({ stalled: false });
		expect(m.evaluate(stalledAt)).toMatchObject({ dueNow: true, missedCount: MAX_MISSED_HEARTBEATS, stalled: true });
	});

	it('resets the stall budget after a successful send', () => {
		const m = monitor();
		m.recordSent(0, null);
		m.evaluate(HEARTBEAT_INTERVAL_MS * (MAX_MISSED_HEARTBEATS + 1));
		expect(m.missedCount).toBe(MAX_MISSED_HEARTBEATS);
		m.recordSent(HEARTBEAT_INTERVAL_MS * (MAX_MISSED_HEARTBEATS + 1) + 1, null);
		expect(m.evaluate(HEARTBEAT_INTERVAL_MS * (MAX_MISSED_HEARTBEATS + 1) + 2)).toMatchObject({
			dueNow: false,
			missedCount: 0,
			stalled: false,
		});
	});
});

describe('evaluateStopConditions', () => {
	it('reports nothing when every input is healthy', () => {
		expect(
			evaluateStopConditions({
				consentRevoked: false,
				meetingEnded: false,
				diskFreeBytes: 10 * 1024 ** 3,
				diskFloorBytes: 1024 ** 3,
				heartbeatStalled: false,
				crashRecoveryMarker: false,
			}),
		).toEqual({ mustStop: false, conditions: [] });
	});

	it('forces a stop for each condition individually', () => {
		const healthy = {
			consentRevoked: false,
			meetingEnded: false,
			diskFreeBytes: 10 * 1024 ** 3 as number | null,
			diskFloorBytes: 1024 ** 3,
			heartbeatStalled: false,
			crashRecoveryMarker: false,
		};
		expect(evaluateStopConditions({ ...healthy, consentRevoked: true }).conditions).toEqual(['consent_revoked']);
		expect(evaluateStopConditions({ ...healthy, meetingEnded: true }).conditions).toEqual(['meeting_ended']);
		expect(
			evaluateStopConditions({ ...healthy, diskFreeBytes: healthy.diskFloorBytes - 1 }).conditions,
		).toEqual(['disk_floor_breached']);
		expect(evaluateStopConditions({ ...healthy, heartbeatStalled: true }).conditions).toEqual(['heartbeat_stalled']);
		expect(evaluateStopConditions({ ...healthy, crashRecoveryMarker: true }).conditions).toEqual([
			'crash_recovery_pending',
		]);
	});

	it('treats an unprovable disk probe as its own stop condition, never as healthy space', () => {
		const decision = evaluateStopConditions({
			consentRevoked: false,
			meetingEnded: false,
			diskFreeBytes: null,
			diskFloorBytes: 1024 ** 3,
			heartbeatStalled: false,
			crashRecoveryMarker: false,
		});
		expect(decision.mustStop).toBe(true);
		expect(decision.conditions).toEqual(['disk_probe_failed']);
	});

	it('lists ALL detected conditions in the fixed priority order', () => {
		// diskFreeBytes 0 sits below the floor (floor breach + probe failure are
		// mutually exclusive inputs — a null probe is the probe_failed case).
		const decision = evaluateStopConditions({
			consentRevoked: true,
			meetingEnded: true,
			diskFreeBytes: 0,
			diskFloorBytes: 1024 ** 3,
			heartbeatStalled: true,
			crashRecoveryMarker: true,
		});
		expect(decision.conditions).toEqual([
			'consent_revoked',
			'meeting_ended',
			'disk_floor_breached',
			'heartbeat_stalled',
			'crash_recovery_pending',
		]);
		expect(decision.conditions).toEqual(
			STOP_CONDITION_PRIORITY.filter((c) => decision.conditions.includes(c)),
		);
		expect(decision.conditions[0]).toBe('consent_revoked');
		expect(decision.mustStop).toBe(true);
	});
});

describe('crash-recovery marker', () => {
	const marker = {
		schema: CRASH_MARKER_SCHEMA,
		meetingId: 42,
		captureDir: '/tmp/setjoin-capture',
		startedAtUnixMs: 1_000,
		lastHeartbeatSeq: 9,
	} as const;

	it('round-trips through encode/parse', () => {
		expect(parseCrashMarker(encodeCrashMarker(marker))).toEqual(marker);
	});

	it('parses to null (fail-closed) on tampering, schema drift, or shape problems', () => {
		expect(parseCrashMarker(null)).toBeNull();
		expect(parseCrashMarker('not json')).toBeNull();
		expect(parseCrashMarker('{"schema":"other"}')).toBeNull();
		const tampered = JSON.parse(encodeCrashMarker(marker)) as Record<string, unknown>;
		tampered.meetingId = 0;
		expect(parseCrashMarker(JSON.stringify(tampered))).toBeNull();
		const emptyDir = JSON.parse(encodeCrashMarker(marker)) as Record<string, unknown>;
		emptyDir.captureDir = '';
		expect(parseCrashMarker(JSON.stringify(emptyDir))).toBeNull();
		const negativeSeq = JSON.parse(encodeCrashMarker(marker)) as Record<string, unknown>;
		negativeSeq.lastHeartbeatSeq = -1;
		expect(parseCrashMarker(JSON.stringify(negativeSeq))).toBeNull();
	});
});
