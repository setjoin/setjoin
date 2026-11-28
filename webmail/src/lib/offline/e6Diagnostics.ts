// E6 diagnostics bounds (plan R4 "E6 reproducible comparison", diagnostics
// paragraph; authority: retired-docs:superpowers/plans/2026-08-11-connectivity-aware-sync-resource-qos.md).
//
// The E0–E3 allowlisted schema is the privacy-safe decision record
// (connectivity-aware-sync-decision.schema.json) plus the finite
// work-contract enums (`PAUSE_REASONS`, `OPTIONAL_WORK_CLASSES`). No export
// pipeline existed before this module, so this module IS the enforcement
// point for the plan's diagnostics bounds:
//
// - At most 1,000 records and 1 MiB per device; seven-day expiry; oldest
//   eviction whenever ANY limit is hit.
// - Export is at most 1 MiB with omitted-count metadata.
// - Exporter failure can never block mail and never enqueues retries: an
//   export is exactly one best-effort attempt; a failure is returned, never
//   thrown into a mail path, and no retry queue exists to grow.
// - Metric labels are a finite enum (the plan §8 required metrics); unknown
//   labels and malformed records are rejected before they are stored.
// - Cross-user aggregates require at least 10 DISTINCT authorized
//   contributors per released bucket, otherwise the bucket is suppressed.
//   Contributor accounting uses only opaque tokens inside the existing
//   authenticated authority; tokens are never exported — a released bucket
//   carries counts and sums only. Unavailable authorization proof means the
//   bucket is omitted (fail closed).
//
// Pure module: bounds are a restriction, not a feature, so nothing here is
// flag-gated and nothing here performs I/O. Wiring the sink into the
// coordinator event stream / a real exporter endpoint is a named follow-up
// for the E6 sustained-evidence slice.
import { isOptionalWorkClass, isPauseReason, type OptionalWorkClass, type PauseReason } from './work-contract';

export const E6_DIAGNOSTICS_SCHEMA_VERSION = 1 as const;

/** Plan bound: maximum 1,000 records per device. */
export const MAX_DIAGNOSTIC_RECORDS_PER_DEVICE = 1_000 as const;
/** Plan bound: maximum 1 MiB of diagnostic records per device. */
export const MAX_DIAGNOSTIC_BYTES_PER_DEVICE = 1_048_576 as const;
/** Plan bound: seven-day record expiry. */
export const DIAGNOSTIC_RECORD_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Plan bound: one export is at most 1 MiB. */
export const MAX_EXPORT_BYTES = 1_048_576 as const;
/** Plan bound: released cross-user buckets need >= 10 distinct contributors. */
export const MIN_AGGREGATE_CONTRIBUTORS = 10 as const;
/** Exactly one attempt per export: no retry queue may grow. */
export const MAX_EXPORT_ATTEMPTS = 1 as const;

/**
 * The finite metric-label enum: exactly the plan §8 required bounded
 * counters/histograms. High-cardinality job/account IDs and content are not
 * representable — an unknown label is rejected, never coerced.
 */
export const E6_METRIC_LABELS = [
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
] as const;
export type E6MetricLabel = (typeof E6_METRIC_LABELS)[number];

export function isE6MetricLabel(value: unknown): value is E6MetricLabel {
	return typeof value === 'string' && (E6_METRIC_LABELS as readonly string[]).includes(value);
}

const COUNTER_METRICS: ReadonlySet<string> = new Set(['request-count', 'checkpoint-count', 'pause-reason', 'cache-evictions']);

export const E6_METRIC_KINDS = ['counter', 'histogram'] as const;
export type E6MetricKind = (typeof E6_METRIC_KINDS)[number];

function isE6MetricKind(value: unknown): value is E6MetricKind {
	return typeof value === 'string' && (E6_METRIC_KINDS as readonly string[]).includes(value);
}

/** One allowlisted diagnostic record. Exact keys; dimensions are finite enums. */
export interface E6DiagnosticRecord {
	schemaVersion: typeof E6_DIAGNOSTICS_SCHEMA_VERSION;
	metric: E6MetricLabel;
	kind: E6MetricKind;
	/** Non-negative bounded observation/counter value. Never an identifier. */
	value: number;
	/** Required exactly for the `pause-reason` metric; forbidden otherwise. */
	reason?: PauseReason;
	/** Required exactly for the `queue-age` metric; forbidden otherwise. */
	workClass?: OptionalWorkClass;
	/** Canonical UTC timestamp; expiry is computed against this. */
	recordedAtUtc: string;
}

const UTC_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function isRecordObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Parse a candidate diagnostic record against the allowlist. Returns null for
 * unknown metric labels, unknown dimension values, malformed timestamps, or
 * any extra/missing field — the rejection is the bound, so callers cannot
 * store unlisted telemetry even accidentally.
 */
export function parseE6DiagnosticRecord(value: unknown): E6DiagnosticRecord | null {
	if (!isRecordObject(value)) return null;
	const hasReason = Object.prototype.hasOwnProperty.call(value, 'reason');
	const hasWorkClass = Object.prototype.hasOwnProperty.call(value, 'workClass');
	// Exact keys: the five base fields plus, at most, the two finite dimension
	// fields. Any other key rejects the record outright.
	const expectedKeys = [
		'kind',
		'metric',
		'recordedAtUtc',
		'schemaVersion',
		'value',
		...(hasReason ? ['reason'] : []),
		...(hasWorkClass ? ['workClass'] : []),
	].sort();
	const keys = Object.keys(value).sort();
	if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) return null;
	if (value.schemaVersion !== E6_DIAGNOSTICS_SCHEMA_VERSION) return null;
	if (!isE6MetricLabel(value.metric)) return null;
	if (!isE6MetricKind(value.kind)) return null;
	// Counters and histograms must agree with the per-metric kind table so a
	// caller cannot relabel a free-form gauge into the allowlist.
	if ((COUNTER_METRICS.has(value.metric) ? 'counter' : 'histogram') !== value.kind) return null;
	if (typeof value.value !== 'number' || !Number.isSafeInteger(value.value) || value.value < 0) return null;
	if (typeof value.recordedAtUtc !== 'string' || !UTC_MS_RE.test(value.recordedAtUtc) || !Number.isFinite(Date.parse(value.recordedAtUtc))) return null;
	if (value.metric === 'pause-reason') {
		if (!hasReason || !isPauseReason(value.reason)) return null;
	} else if (hasReason) {
		return null;
	}
	if (value.metric === 'queue-age') {
		if (!hasWorkClass || !isOptionalWorkClass(value.workClass)) return null;
	} else if (hasWorkClass) {
		return null;
	}
	const record: E6DiagnosticRecord = {
		schemaVersion: E6_DIAGNOSTICS_SCHEMA_VERSION,
		metric: value.metric,
		kind: value.kind,
		value: value.value,
		recordedAtUtc: value.recordedAtUtc,
	};
	if (hasReason) record.reason = value.reason as PauseReason;
	if (hasWorkClass) record.workClass = value.workClass as OptionalWorkClass;
	return record;
}

/** Export envelope: allowlisted records plus omitted-count metadata, <= 1 MiB. */
export interface E6ExportEnvelope {
	schemaVersion: typeof E6_DIAGNOSTICS_SCHEMA_VERSION;
	exportedAtUtc: string;
	records: E6DiagnosticRecord[];
	/** How many stored records did not fit the 1 MiB export bound. */
	omitted: { count: number };
}

export interface E6StoreStats {
	recordCount: number;
	byteCount: number;
}

export interface E6DiagnosticsStore {
	append(value: unknown): { accepted: boolean };
	exportEnvelope(): E6ExportEnvelope;
	stats(): E6StoreStats;
}

interface StoredRecord {
	record: E6DiagnosticRecord;
	byteSize: number;
	insertion: number;
}

const textEncoder = new TextEncoder();

function byteSizeOf(text: string): number {
	return textEncoder.encode(text).length;
}

/**
 * The bounded per-device diagnostics store. Every entry point enforces the
 * plan bounds: unknown labels are rejected at append, seven-day expiry prunes
 * on every operation, and whenever ANY limit (records or bytes) is hit the
 * OLDEST records are evicted until all limits hold again.
 */
export function createE6DiagnosticsStore(clock: { nowUtcMs(): number }): E6DiagnosticsStore {
	// Kept ordered by (recordedAtUtc, insertion): oldest-first, so expiry and
	// any-limit eviction are head removals.
	const records: StoredRecord[] = [];
	let bytes = 0;
	let insertionCounter = 0;

	function timeOf(entry: StoredRecord): number {
		return Date.parse(entry.record.recordedAtUtc);
	}

	function isOlderOrEqual(candidate: StoredRecord, than: StoredRecord): boolean {
		const a = timeOf(candidate);
		const b = timeOf(than);
		if (a !== b) return a < b;
		return candidate.insertion <= than.insertion;
	}

	function insertOrdered(entry: StoredRecord): void {
		let low = 0;
		let high = records.length;
		while (low < high) {
			const mid = (low + high) >> 1;
			if (isOlderOrEqual(records[mid], entry)) low = mid + 1;
			else high = mid;
		}
		records.splice(low, 0, entry);
	}

	function pruneExpired(nowMs: number): void {
		while (records.length > 0 && nowMs - timeOf(records[0]) >= DIAGNOSTIC_RECORD_TTL_MS) {
			bytes -= records[0].byteSize;
			records.shift();
		}
	}

	function evictToLimits(): void {
		// Oldest eviction whenever ANY limit is hit; loop until ALL hold.
		while (
			records.length > 0 &&
			(records.length > MAX_DIAGNOSTIC_RECORDS_PER_DEVICE || bytes > MAX_DIAGNOSTIC_BYTES_PER_DEVICE)
		) {
			bytes -= records[0].byteSize;
			records.shift();
		}
	}

	return {
		append(value: unknown): { accepted: boolean } {
			const parsed = parseE6DiagnosticRecord(value);
			if (!parsed) return { accepted: false };
			const nowMs = clock.nowUtcMs();
			const byteSize = byteSizeOf(JSON.stringify(parsed));
			insertOrdered({ record: parsed, byteSize, insertion: insertionCounter });
			bytes += byteSize;
			insertionCounter += 1;
			// Prune AFTER the insert too: an already-expired record is accepted by
			// the allowlist but never served by the store.
			pruneExpired(nowMs);
			evictToLimits();
			return { accepted: true };
		},
		exportEnvelope(): E6ExportEnvelope {
			const nowMs = clock.nowUtcMs();
			pruneExpired(nowMs);
			const exportedAtUtc = new Date(nowMs).toISOString();
			// Oldest-first so a too-large store exports its most valuable recent
			// records and counts the dropped tail honestly.
			const head = `{"schemaVersion":${E6_DIAGNOSTICS_SCHEMA_VERSION},"exportedAtUtc":${JSON.stringify(exportedAtUtc)},"records":[`;
			const tail = `],"omitted":{"count":OMITTED}}`;
			const included: E6DiagnosticRecord[] = [];
			let used = byteSizeOf(head) + byteSizeOf(tail);
			let omitted = 0;
			for (const entry of records) {
				const serialized = byteSizeOf(JSON.stringify(entry.record)) + (included.length === 0 ? 0 : 1);
				if (used + serialized > MAX_EXPORT_BYTES) {
					omitted = records.length - included.length;
					break;
				}
				included.push(entry.record);
				used += serialized;
			}
			return {
				schemaVersion: E6_DIAGNOSTICS_SCHEMA_VERSION,
				exportedAtUtc,
				records: included,
				omitted: { count: omitted },
			};
		},
		stats(): E6StoreStats {
			return { recordCount: records.length, byteCount: bytes };
		},
	};
}

export type E6ExportOutcome = { ok: true } | { ok: false; reason: 'exporter-failed' };

export interface E6DiagnosticsExporter {
	submitExport(): Promise<E6ExportOutcome>;
}

/**
 * Fire-and-forget exporter boundary. `send` is attempted EXACTLY once
 * (MAX_EXPORT_ATTEMPTS = 1): a sync throw or a rejection is caught and
 * returned as a failed outcome — it never propagates into a mail path, and
 * because no retry queue exists, repeated failures cannot grow any backlog.
 */
export function createE6DiagnosticsExporter(
	store: E6DiagnosticsStore,
	send: (envelope: E6ExportEnvelope) => Promise<void>,
): E6DiagnosticsExporter {
	return {
		async submitExport(): Promise<E6ExportOutcome> {
			// exportEnvelope is total (it never throws); the failure boundary is
			// the sink itself.
			const envelope = store.exportEnvelope();
			try {
				await send(envelope);
				return { ok: true };
			} catch {
				// One attempt only: the failure is reported, never re-enqueued.
				return { ok: false, reason: 'exporter-failed' };
			}
		},
	};
}

export interface E6Contribution {
	/** Bucket key: `<metric>` or `<metric>:<finite dimension value>`. */
	bucketKey: string;
	/** Opaque contributor token from the existing authenticated authority. */
	contributorToken: string;
	/** Authorization proof from the existing authenticated authority. */
	authorized: boolean;
	value: number;
}

export type E6ReleasedBucket = {
	status: 'released';
	bucketKey: string;
	distinctContributors: number;
	recordCount: number;
	sum: number;
};

export type E6SuppressedBucket = {
	status: 'suppressed';
	bucketKey: string;
	reason: 'below-minimum-cohort' | 'unauthorized-contribution' | 'malformed-bucket';
};

export interface E6AggregateDisposition {
	released: E6ReleasedBucket[];
	suppressed: E6SuppressedBucket[];
}

function parseBucketKey(bucketKey: string): { metric: E6MetricLabel; dimension: string | null } | null {
	if (typeof bucketKey !== 'string' || bucketKey.length === 0 || bucketKey.length > 128) return null;
	const separator = bucketKey.indexOf(':');
	const metric = separator === -1 ? bucketKey : bucketKey.slice(0, separator);
	if (!isE6MetricLabel(metric)) return null;
	if (separator === -1) {
		if (metric === 'pause-reason' || metric === 'queue-age') return null;
		return { metric, dimension: null };
	}
	const dimension = bucketKey.slice(separator + 1);
	if (dimension.length === 0 || dimension.includes(':')) return null;
	if (metric === 'pause-reason' && !isPauseReason(dimension)) return null;
	else if (metric === 'queue-age' && !isOptionalWorkClass(dimension)) return null;
	else if (metric !== 'pause-reason' && metric !== 'queue-age') return null;
	return { metric, dimension };
}

/**
 * Cross-user aggregate release. Buckets need at least MIN_AGGREGATE_CONTRIBUTORS
 * DISTINCT authorized contributors or they are suppressed; a single
 * unauthorized contribution suppresses its whole bucket (unavailable proof
 * means omit). Contributor tokens are used ONLY to count distinctness inside
 * this call — they never appear in any released bucket, so contributor
 * accounting never becomes identity telemetry.
 */
export function releaseCrossUserBuckets(contributions: readonly E6Contribution[]): E6AggregateDisposition {
	const released: E6ReleasedBucket[] = [];
	const suppressed: E6SuppressedBucket[] = [];
	const buckets = new Map<string, E6Contribution[]>();
	for (const contribution of contributions) {
		const bucket = buckets.get(contribution.bucketKey);
		if (bucket) bucket.push(contribution);
		else buckets.set(contribution.bucketKey, [contribution]);
	}
	for (const [bucketKey, bucketContributions] of buckets) {
		if (!parseBucketKey(bucketKey)) {
			suppressed.push({ status: 'suppressed', bucketKey, reason: 'malformed-bucket' });
			continue;
		}
		if (bucketContributions.some((contribution) => !contribution.authorized)) {
			suppressed.push({ status: 'suppressed', bucketKey, reason: 'unauthorized-contribution' });
			continue;
		}
		const distinct = new Set<string>();
		let sum = 0;
		for (const contribution of bucketContributions) {
			distinct.add(contribution.contributorToken);
			sum += contribution.value;
		}
		if (distinct.size < MIN_AGGREGATE_CONTRIBUTORS) {
			suppressed.push({ status: 'suppressed', bucketKey, reason: 'below-minimum-cohort' });
			continue;
		}
		released.push({
			status: 'released',
			bucketKey,
			distinctContributors: distinct.size,
			recordCount: bucketContributions.length,
			sum,
		});
	}
	return { released, suppressed };
}
