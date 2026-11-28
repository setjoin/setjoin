/**
 * CAS-E6-DIAGNOSTIC-BOUNDS / CAS-E6-EXPORTER-FAILURE /
 * CAS-E6-METRIC-LABEL-ALLOWLIST / CAS-E6-SMALL-COHORT-SUPPRESSION —
 * E6 diagnostics verification bindings (core lane, deterministic).
 *
 * Plan R4 diagnostics bounds, enforced by `e6Diagnostics.ts`:
 * - at most 1,000 records and 1 MiB per device, seven-day expiry, oldest
 *   eviction when ANY limit is hit;
 * - export <= 1 MiB with omitted-count metadata;
 * - exporter failure never blocks mail and never enqueues retries;
 * - finite metric-label enum, unknown labels rejected;
 * - cross-user buckets need >= 10 distinct authorized contributors, else
 *   suppressed; contributor tokens never leave the accounting.
 *
 * The sink wiring into the coordinator event stream is a named follow-up for
 * the E6 sustained-evidence slice; these bounds are a restriction, so nothing
 * here is flag-gated.
 */
import { describe, it, expect } from 'vitest';
import {
	DIAGNOSTIC_RECORD_TTL_MS,
	E6_METRIC_LABELS,
	MAX_DIAGNOSTIC_BYTES_PER_DEVICE,
	MAX_DIAGNOSTIC_RECORDS_PER_DEVICE,
	MAX_EXPORT_ATTEMPTS,
	MAX_EXPORT_BYTES,
	MIN_AGGREGATE_CONTRIBUTORS,
	createE6DiagnosticsExporter,
	createE6DiagnosticsStore,
	parseE6DiagnosticRecord,
	releaseCrossUserBuckets,
	type E6Contribution,
} from './e6Diagnostics';

function utc(ms: number): string {
	return new Date(ms).toISOString();
}

function makeStore(nowMs = 1_800_000_000_000) {
	const clock = { nowUtcMs: () => nowMs };
	return { clock, store: createE6DiagnosticsStore(clock), nowMs };
}

function record(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		schemaVersion: 1,
		metric: 'request-count',
		kind: 'counter',
		value: 1,
		recordedAtUtc: utc(1_800_000_000_000),
		...overrides,
	};
}

describe('CAS-E6-DIAGNOSTIC-BOUNDS', () => {
	it('freezes the plan bounds as exported constants', () => {
		expect(MAX_DIAGNOSTIC_RECORDS_PER_DEVICE).toBe(1_000);
		expect(MAX_DIAGNOSTIC_BYTES_PER_DEVICE).toBe(1_048_576);
		expect(DIAGNOSTIC_RECORD_TTL_MS).toBe(7 * 24 * 60 * 60 * 1000);
		expect(MAX_EXPORT_BYTES).toBe(1_048_576);
		expect(MIN_AGGREGATE_CONTRIBUTORS).toBe(10);
		expect(MAX_EXPORT_ATTEMPTS).toBe(1);
	});

	it('evicts the oldest record when the 1,000-record limit is hit', () => {
		const { store } = makeStore();
		for (let index = 0; index < MAX_DIAGNOSTIC_RECORDS_PER_DEVICE; index += 1) {
			expect(store.append(record({ value: index, recordedAtUtc: utc(1_800_000_000_000 + index) })).accepted).toBe(true);
		}
		expect(store.stats().recordCount).toBe(MAX_DIAGNOSTIC_RECORDS_PER_DEVICE);
		// One more: the OLDEST (earliest timestamp) must be evicted, keeping the
		// store at exactly the cap.
		expect(store.append(record({ value: 9_999, recordedAtUtc: utc(1_800_000_000_000 + MAX_DIAGNOSTIC_RECORDS_PER_DEVICE) })).accepted).toBe(true);
		expect(store.stats().recordCount).toBe(MAX_DIAGNOSTIC_RECORDS_PER_DEVICE);
		const envelope = store.exportEnvelope();
		const values = envelope.records.map((entry) => entry.value);
		expect(values).not.toContain(0);
		expect(values[0]).toBe(1);
		expect(values[values.length - 1]).toBe(9_999);
		expect(envelope.omitted.count).toBe(0);
	});

	it('holds both store limits under a backlog that exceeds them many times over', () => {
		const { store } = makeStore();
		// 20,000 valid records exceed both the 1,000-record and the 1 MiB bound.
		// With the allowlisted record shape (~150 bytes) the record cap binds
		// first; BOTH invariants must hold after every append.
		const total = 20_000;
		for (let index = 0; index < total; index += 1) {
			store.append(record({ metric: 'useful-bytes', kind: 'histogram', value: index, recordedAtUtc: utc(1_800_000_000_000 + index) }));
		}
		const stats = store.stats();
		expect(stats.recordCount).toBe(MAX_DIAGNOSTIC_RECORDS_PER_DEVICE);
		expect(stats.byteCount).toBeLessThanOrEqual(MAX_DIAGNOSTIC_BYTES_PER_DEVICE);
		// Oldest eviction: only the newest window survives, in order.
		const envelope = store.exportEnvelope();
		expect(envelope.records[0].value).toBe(total - MAX_DIAGNOSTIC_RECORDS_PER_DEVICE);
		expect(envelope.records[envelope.records.length - 1].value).toBe(total - 1);
	});

	it('expires records after seven days, including already-expired appends', () => {
		const early = makeStore(1_800_000_000_000);
		early.store.append(record({}));
		expect(early.store.stats().recordCount).toBe(1);
		// A store read one millisecond past the TTL must not serve the record.
		const lateClock = { nowUtcMs: () => 1_800_000_000_000 + DIAGNOSTIC_RECORD_TTL_MS + 1 };
		const longLived = createE6DiagnosticsStore(lateClock);
		// Even appends of already-expired records are never served.
		longLived.append(record({ recordedAtUtc: utc(1_800_000_000_000) }));
		longLived.append(record({ value: 2, recordedAtUtc: utc(1_800_000_000_000) }));
		expect(longLived.stats().recordCount).toBe(0);
		expect(longLived.exportEnvelope().records).toHaveLength(0);
		expect(longLived.exportEnvelope().omitted.count).toBe(0);
		// The early store, read before expiry, still holds its record (expiry is
		// time-, not counter-based).
		expect(early.store.stats().recordCount).toBe(1);
	});

	it('exports at most 1 MiB with exact omitted-count metadata', () => {
		const { store } = makeStore();
		// Pause-reason records are the largest allowlisted shape; 40,000 of them
		// far exceed the store caps, so the store holds its bounded newest set.
		const reasons = ['networkUnavailable', 'meteredNetwork', 'backoff', 'thermal'] as const;
		for (let index = 0; index < 40_000; index += 1) {
			store.append(record({
				metric: 'pause-reason',
				kind: 'counter',
				reason: reasons[index % reasons.length],
				value: 1,
				recordedAtUtc: utc(1_800_000_000_000 + (index % (DIAGNOSTIC_RECORD_TTL_MS - 1))),
			}));
		}
		const envelope = store.exportEnvelope();
		const serialized = JSON.stringify(envelope);
		expect(new TextEncoder().encode(serialized).length).toBeLessThanOrEqual(MAX_EXPORT_BYTES);
		// The omitted-count metadata is exact: exported + omitted === stored.
		expect(envelope.records.length + envelope.omitted.count).toBe(store.stats().recordCount);
		// The envelope is complete when the store already fits the export bound.
		expect(envelope.omitted.count).toBe(0);
		expect(envelope.records).toHaveLength(MAX_DIAGNOSTIC_RECORDS_PER_DEVICE);
	});

	it('accepts only fully allowlisted records and never throws on junk', () => {
		const { store } = makeStore();
		expect(store.append(record()).accepted).toBe(true);
		expect(store.append({ not: 'a record' }).accepted).toBe(false);
		expect(store.append(null).accepted).toBe(false);
		expect(store.append('request-count').accepted).toBe(false);
		expect(store.stats().recordCount).toBe(1);
	});
});

describe('CAS-E6-EXPORTER-FAILURE', () => {
	it('returns a failed outcome when the sink throws or rejects — never an exception', async () => {
		const { store } = makeStore();
		store.append(record());
		const throwing = createE6DiagnosticsExporter(store, () => {
			throw new Error('sink exploded');
		});
		await expect(throwing.submitExport()).resolves.toEqual({ ok: false, reason: 'exporter-failed' });
		const rejecting = createE6DiagnosticsExporter(store, async () => {
			await Promise.resolve();
			throw new Error('network down');
		});
		await expect(rejecting.submitExport()).resolves.toEqual({ ok: false, reason: 'exporter-failed' });
	});

	it('repeated exporter failures never enqueue retries or grow any backlog', async () => {
		const { store } = makeStore();
		const failing = createE6DiagnosticsExporter(store, async () => {
			throw new Error('persistent outage');
		});
		for (let attempt = 0; attempt < 100; attempt += 1) {
			await expect(failing.submitExport()).resolves.toEqual({ ok: false, reason: 'exporter-failed' });
		}
		// No retry queue exists: the store stats are unchanged and nothing was
		// consumed or duplicated by the failed attempts.
		expect(store.stats()).toEqual({ recordCount: 0, byteCount: 0 });
	});

	it('a healthy sink exports exactly once per submit and mail paths keep working', async () => {
		const { store } = makeStore();
		store.append(record());
		let sent = 0;
		const exporter = createE6DiagnosticsExporter(store, async (envelope) => {
			sent += 1;
			expect(envelope.records).toHaveLength(1);
		});
		await expect(exporter.submitExport()).resolves.toEqual({ ok: true });
		expect(sent).toBe(1);
		// The failure isolation never disturbed the store: appends still work.
		expect(store.append(record({ value: 2 })).accepted).toBe(true);
		expect(store.stats().recordCount).toBe(2);
	});
});

describe('CAS-E6-METRIC-LABEL-ALLOWLIST', () => {
	it('exposes exactly the plan §8 finite metric labels', () => {
		expect(E6_METRIC_LABELS).toEqual([
			'time-to-cached-list',
			'time-to-current',
			'useful-bytes',
			'total-bytes',
			'resumed-bytes',
			'request-count',
			'delta-fallback-ratio',
			'checkpoint-count',
			'pause-reason',
			'queue-age',
			'cpu-time',
			'peak-rss',
			'cache-bytes',
			'cache-evictions',
			'critical-p50',
			'critical-p95',
			'critical-p99',
		]);
	});

	it('rejects unknown labels instead of storing them', () => {
		expect(parseE6DiagnosticRecord(record({ metric: 'job-12345' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'account:42' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'subject-lines' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: '' }))).toBeNull();
		const { store } = makeStore();
		expect(store.append(record({ metric: 'job-12345' })).accepted).toBe(false);
		expect(store.stats().recordCount).toBe(0);
	});

	it('enforces the finite dimension enums and per-metric dimensions', () => {
		expect(parseE6DiagnosticRecord(record({ metric: 'pause-reason', kind: 'counter', reason: 'networkUnavailable' }))).not.toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'pause-reason', kind: 'counter' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'pause-reason', kind: 'counter', reason: 'made-up-reason' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'request-count', reason: 'networkUnavailable' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'queue-age', kind: 'histogram', workClass: 'background' }))).not.toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'queue-age', kind: 'histogram', workClass: 'sneaky-class' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'cpu-time', workClass: 'background' }))).toBeNull();
	});

	it('rejects malformed values, kinds, timestamps, extra fields, and ahead schema versions', () => {
		expect(parseE6DiagnosticRecord(record({ value: -1 }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ value: 1.5 }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ value: Number.MAX_SAFE_INTEGER + 1 }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ kind: 'gauge' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'cpu-time', kind: 'counter' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ recordedAtUtc: 'not-a-time' }))).toBeNull();
		expect(parseE6DiagnosticRecord(record({ recordedAtUtc: '2026-09-18T00:00:00+00:00' }))).toBeNull();
		expect(parseE6DiagnosticRecord({ ...record(), extra: 'field' })).toBeNull();
		expect(parseE6DiagnosticRecord({ ...record(), schemaVersion: 2 })).toBeNull();
		expect(parseE6DiagnosticRecord(record({ metric: 'pause-reason', kind: 'counter', reason: 'networkUnavailable', workClass: 'background' }))).toBeNull();
	});

	it('keeps oldest-first order even when an older record arrives later', () => {
		const { store } = makeStore();
		store.append(record({ value: 10, recordedAtUtc: utc(1_800_000_000_000 + 10) }));
		store.append(record({ value: 12, recordedAtUtc: utc(1_800_000_000_000 + 12) }));
		// An out-of-order append lands in the ordered interior, not the head.
		store.append(record({ value: 11, recordedAtUtc: utc(1_800_000_000_000 + 11) }));
		const envelope = store.exportEnvelope();
		expect(envelope.records.map((entry) => entry.value)).toEqual([10, 11, 12]);
	});
});

describe('CAS-E6-SMALL-COHORT-SUPPRESSION', () => {
	function contributions(distinct: number, bucketKey = 'request-count', authorized = true): E6Contribution[] {
		return Array.from({ length: distinct }, (_, index) => ({
			bucketKey,
			contributorToken: `contributor-${index}`,
			authorized,
			value: 1,
		}));
	}

	it('suppresses a bucket with fewer than 10 distinct contributors', () => {
		const disposition = releaseCrossUserBuckets(contributions(MIN_AGGREGATE_CONTRIBUTORS - 1));
		expect(disposition.released).toEqual([]);
		expect(disposition.suppressed).toEqual([
			{ status: 'suppressed', bucketKey: 'request-count', reason: 'below-minimum-cohort' },
		]);
	});

	it('releases exactly at the 10-distinct-contributor threshold', () => {
		const disposition = releaseCrossUserBuckets(contributions(MIN_AGGREGATE_CONTRIBUTORS));
		expect(disposition.suppressed).toEqual([]);
		expect(disposition.released).toEqual([
			{ status: 'released', bucketKey: 'request-count', distinctContributors: 10, recordCount: 10, sum: 10 },
		]);
	});

	it('counts DISTINCT contributors, so repeat contributions do not buy release', () => {
		const repeats: E6Contribution[] = Array.from({ length: 40 }, (_, index) => ({
			bucketKey: 'useful-bytes',
			contributorToken: `contributor-${index % 5}`,
			authorized: true,
			value: 2,
		}));
		const disposition = releaseCrossUserBuckets(repeats);
		expect(disposition.released).toEqual([]);
		expect(disposition.suppressed[0]).toEqual({
			status: 'suppressed',
			bucketKey: 'useful-bytes',
			reason: 'below-minimum-cohort',
		});
	});

	it('one unauthorized contribution suppresses its whole bucket', () => {
		const bucket = [
			...contributions(MIN_AGGREGATE_CONTRIBUTORS + 5),
			{ bucketKey: 'request-count', contributorToken: 'contributor-x', authorized: false, value: 1 },
		];
		const disposition = releaseCrossUserBuckets(bucket);
		expect(disposition.released).toEqual([]);
		expect(disposition.suppressed).toEqual([
			{ status: 'suppressed', bucketKey: 'request-count', reason: 'unauthorized-contribution' },
		]);
	});

	it('never exports contributor tokens — released buckets carry counts and sums only', () => {
		const bucket = contributions(MIN_AGGREGATE_CONTRIBUTORS + 2).map((entry, index) => ({
			...entry,
			contributorToken: `secret-identity-${index}`,
			value: index,
		}));
		const disposition = releaseCrossUserBuckets(bucket);
		expect(disposition.released).toHaveLength(1);
		const serialized = JSON.stringify(disposition.released);
		expect(serialized).not.toContain('secret-identity');
		expect(serialized).not.toContain('contributor');
		expect(disposition.released[0]).toEqual({
			status: 'released',
			bucketKey: 'request-count',
			distinctContributors: 12,
			recordCount: 12,
			sum: 66,
		});
	});

	it('dimension buckets accept only finite enum values; malformed keys are suppressed', () => {
		const good = contributions(MIN_AGGREGATE_CONTRIBUTORS, 'pause-reason:networkUnavailable');
		const bad = contributions(3, 'queue-age:not-a-class');
		const malformed = contributions(3, 'job-12345:whatever');
		const nondimensional = contributions(3, 'pause-reason');
		const disposition = releaseCrossUserBuckets([...good, ...bad, ...malformed, ...nondimensional]);
		expect(disposition.released).toEqual([
			{ status: 'released', bucketKey: 'pause-reason:networkUnavailable', distinctContributors: 10, recordCount: 10, sum: 10 },
		]);
		const reasons = new Map(disposition.suppressed.map((entry) => [entry.bucketKey, entry.reason]));
		expect(reasons.get('queue-age:not-a-class')).toBe('malformed-bucket');
		expect(reasons.get('job-12345:whatever')).toBe('malformed-bucket');
		expect(reasons.get('pause-reason')).toBe('malformed-bucket');
	});

	it('suppresses every other malformed bucket-key shape', () => {
		const emptyKey = contributions(3, '');
		const overlongKey = contributions(3, `request-count:${'x'.repeat(200)}`);
		const emptyDimension = contributions(3, 'request-count:');
		const doubleDimension = contributions(3, 'queue-age:background:extra');
		const invalidReasonDimension = contributions(3, 'pause-reason:not-a-reason');
		const dimensionOnPlainMetric = contributions(3, 'cpu-time:background');
		const disposition = releaseCrossUserBuckets([
			...emptyKey,
			...overlongKey,
			...emptyDimension,
			...doubleDimension,
			...invalidReasonDimension,
			...dimensionOnPlainMetric,
		]);
		expect(disposition.released).toEqual([]);
		expect(disposition.suppressed).toHaveLength(6);
		for (const entry of disposition.suppressed) {
			expect(entry.reason).toBe('malformed-bucket');
		}
	});
});
