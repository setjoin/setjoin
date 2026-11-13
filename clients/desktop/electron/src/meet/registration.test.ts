import { describe, expect, it } from 'vitest';

import {
	LOCAL_PACKAGE_SCHEMA,
	MAX_LOCAL_SEGMENTS,
	LocalPackageBuilder,
	LocalPackageBuilderError,
	canonicalJson,
	computeCoverage,
	descriptorDigest,
	validateDescriptor,
	validateSegment,
	type LocalPackageDescriptor,
	type LocalPackageSegment,
	type LocalPackageStart,
	type ObservedSegment,
} from './registration';

const START: LocalPackageStart = {
	meetingId: 42,
	policyMode: 'local_only',
	surfaces: ['microphone'],
	producer: { platform: 'darwin', platformVersion: '25.6.0', captureApiVersion: 'electron-43+chromium-143' },
};

const OBSERVED: ObservedSegment = {
	contentSha256: 'a'.repeat(64),
	byteSize: 960_000,
	mimeType: 'audio/webm',
	codec: 'opus',
	container: 'webm',
};

function verifiedSegment(seq: number, overrides: Partial<LocalPackageSegment> = {}): LocalPackageSegment {
	return {
		seq,
		state: 'verified',
		contentSha256: 'b'.repeat(64),
		byteSize: 1000,
		mimeType: 'audio/webm',
		codec: 'opus',
		container: 'webm',
		interval: { startMs: (seq - 1) * 10_000, endMs: seq * 10_000 },
		wallStartUnixMs: 1000 + (seq - 1) * 10_000,
		wallEndUnixMs: 1000 + seq * 10_000,
		interruptReason: null,
		...overrides,
	};
}

function freshBuilder(): LocalPackageBuilder {
	return new LocalPackageBuilder(START, 1_000);
}

function expectBuilderError(fn: () => unknown, message: RegExp): void {
	expect(fn).toThrow(LocalPackageBuilderError);
	expect(fn).toThrowError(message);
}

describe('segment truth rules (the segment.go port)', () => {
	it('accepts a fully bound verified segment', () => {
		expect(validateSegment(verifiedSegment(1))).toBeNull();
	});

	it('refuses bad identity and non-positive or backwards intervals', () => {
		expect(validateSegment(verifiedSegment(0))).toMatch(/sequence numbers from 1/);
		const backwards = verifiedSegment(1, { interval: { startMs: 100, endMs: 100 } });
		expect(validateSegment(backwards)).toMatch(/not a positive interval/);
		const wallBackwards = verifiedSegment(1, { wallStartUnixMs: 2000, wallEndUnixMs: 1000 });
		expect(validateSegment(wallBackwards)).toMatch(/wall-clock anchors run backwards/);
	});

	it('a capturing segment carries NO completeness claim', () => {
		const capturing = verifiedSegment(1, {
			state: 'capturing',
			contentSha256: null,
			byteSize: null,
			mimeType: null,
			codec: null,
			container: null,
			interruptReason: null,
		});
		expect(validateSegment(capturing)).toBeNull();
		expect(
			validateSegment({ ...capturing, contentSha256: 'c'.repeat(64) }),
		).toMatch(/completeness claim/);
		expect(validateSegment({ ...capturing, byteSize: 10 })).toMatch(/completeness claim/);
	});

	it('a verified segment REQUIRES digest + size + actual MIME/codec/container', () => {
		expect(validateSegment(verifiedSegment(1, { contentSha256: null }))).toMatch(/without a valid sha256/);
		expect(validateSegment(verifiedSegment(1, { contentSha256: 'zz' }))).toMatch(/without a valid sha256/);
		expect(validateSegment(verifiedSegment(1, { byteSize: 0 }))).toMatch(/no byte size/);
		expect(validateSegment(verifiedSegment(1, { mimeType: null }))).toMatch(/missing actual MIME/);
		expect(validateSegment(verifiedSegment(1, { codec: null }))).toMatch(/missing actual MIME/);
		expect(validateSegment(verifiedSegment(1, { container: null }))).toMatch(/missing actual MIME/);
	});

	it('interrupted/failed segments must name why they stopped and keep honest partial bytes', () => {
		const base = verifiedSegment(1, {
			state: 'interrupted',
			mimeType: null,
			codec: null,
			container: null,
			byteSize: 400,
		});
		expect(validateSegment({ ...base, interruptReason: 'meeting_ended' })).toBeNull();
		expect(validateSegment({ ...base, interruptReason: null })).toMatch(/must name why it stopped/);
		expect(
			validateSegment({ ...base, interruptReason: 'x', contentSha256: 'nope' }),
		).toMatch(/not a valid sha256/);
		expect(validateSegment({ ...base, state: 'failed', interruptReason: 'disk full' })).toBeNull();
	});
});

describe('LocalPackageBuilder lifecycle', () => {
	it('records the honest recording snapshot: no digest, no end, null recordingId', () => {
		const builder = freshBuilder();
		builder.openSegment(0, 1_000);
		const snapshot = builder.snapshot(5_000);
		expect(snapshot).toMatchObject({
			schema: LOCAL_PACKAGE_SCHEMA,
			meetingId: 42,
			recordingId: null,
			packageState: 'recording',
			captureMode: 'local_registered',
			policyMode: 'local_only',
			uploadedToDrive: false,
			integrityDigest: null,
			endedAtUnixMs: null,
		});
		expect(snapshot.segments[0]).toMatchObject({ seq: 1, state: 'capturing' });
	});

	it('confirms a capturing segment into verified with the ACTUAL observed identity', () => {
		const builder = freshBuilder();
		const seq = builder.openSegment(0, 1_000);
		const confirmed = builder.confirmSegment(seq, OBSERVED, 60_000, 61_000);
		expect(confirmed).toMatchObject({
			state: 'verified',
			contentSha256: OBSERVED.contentSha256,
			byteSize: OBSERVED.byteSize,
			mimeType: 'audio/webm',
			codec: 'opus',
			container: 'webm',
			interval: { startMs: 0, endMs: 60_000 },
			wallEndUnixMs: 61_000,
		});
	});

	it('rolls back a failed verification instead of leaving a mutated lie', () => {
		const builder = freshBuilder();
		const seq = builder.openSegment(0, 1_000);
		expectBuilderError(
			() => builder.confirmSegment(seq, { ...OBSERVED, mimeType: '' }, 60_000, 61_000),
			/missing actual MIME/,
		);
		expect(builder.snapshot(0).segments[0]).toMatchObject({ state: 'capturing', contentSha256: null });
	});

	it('truthfully stops segments (reason mandatory) and never demotes verified ones', () => {
		const builder = freshBuilder();
		const seq = builder.openSegment(0, 1_000);
		const interrupted = builder.markSegmentNotCompleted(seq, 'interrupted', 'revocation', 30_000, 31_000);
		expect(interrupted).toMatchObject({
			state: 'interrupted',
			interruptReason: 'revocation',
			contentSha256: null,
		});
		const verified = builder.openSegment(10, 1_010);
		builder.confirmSegment(verified, OBSERVED, 40_000, 41_000);
		expectBuilderError(
			() => builder.markSegmentNotCompleted(verified, 'interrupted', 'revocation', 40_000, 41_000),
			/never demoted/,
		);
		expectBuilderError(
			() => builder.markSegmentNotCompleted(builder.openSegment(20, 1_020), 'interrupted', '', 50_000, 51_000),
			/must name why/,
		);
	});

	it('refuses to finalize while any segment is still capturing', () => {
		const builder = freshBuilder();
		builder.openSegment(0, 1_000);
		builder.openSegment(10_000, 11_000);
		expectBuilderError(() => builder.finalize(20_000, 21_000), /2 segment\(s\) still capturing/);
	});

	it('finalizes cleanly: verified coverage, honest gaps, sealed digest, end time bound', () => {
		const builder = freshBuilder();
		const first = builder.openSegment(0, 1_000);
		builder.confirmSegment(first, OBSERVED, 10_000, 11_000);
		const second = builder.openSegment(10_000, 11_000);
		builder.markSegmentNotCompleted(second, 'interrupted', 'revocation', 15_000, 16_000);
		const descriptor = builder.finalize(15_000, 16_000);

		expect(descriptor.packageState).toBe('finalized');
		expect(descriptor.endedAtUnixMs).toBe(16_000);
		expect(descriptor.integrityDigest).toMatch(/^[0-9a-f]{64}$/);
		expect(descriptor.uploadedToDrive).toBe(false);
		// The interrupted segment's window [10s,15s) is a LISTED GAP, never media.
		expect(descriptor.coverage.available).toEqual([{ startMs: 0, endMs: 10_000 }]);
		expect(descriptor.coverage.gaps).toEqual([{ startMs: 10_000, endMs: 15_000 }]);
		expect(validateDescriptor(descriptor)).toBeNull();
	});

	it('stopWithInterrupt forces every open segment to interrupted and finalizes interrupted', () => {
		const builder = freshBuilder();
		const done = builder.openSegment(0, 1_000);
		builder.confirmSegment(done, OBSERVED, 10_000, 11_000);
		builder.openSegment(10_000, 11_000);
		const descriptor = builder.stopWithInterrupt('meeting_ended', 12_000, 12_500);
		expect(descriptor.packageState).toBe('interrupted');
		expect(descriptor.segments.map((s) => s.state)).toEqual(['verified', 'interrupted']);
		expect(descriptor.segments[1].interruptReason).toBe('meeting_ended');
		expect(descriptor.coverage.gaps).toEqual([{ startMs: 10_000, endMs: 12_000 }]);
		expect(validateDescriptor(descriptor)).toBeNull();
	});

	it('is inert after finalize: no further segment mutations', () => {
		const builder = freshBuilder();
		const seq = builder.openSegment(0, 1_000);
		builder.confirmSegment(seq, OBSERVED, 10_000, 11_000);
		builder.finalize(10_000, 11_000);
		expectBuilderError(() => builder.openSegment(10_000, 11_000), /not allowed in package state/);
	});

	it('markRegistered flips finalized → registered with the registration timestamp', () => {
		const builder = freshBuilder();
		const seq = builder.openSegment(0, 1_000);
		builder.confirmSegment(seq, OBSERVED, 10_000, 11_000);
		builder.finalize(10_000, 11_000);
		const registered = builder.markRegistered(10_000, 12_000);
		expect(registered.packageState).toBe('registered');
		expect(registered.registeredAtUnixMs).toBe(12_000);
		expect(registered.uploadedToDrive).toBe(false); // registration ≠ upload
		expect(validateDescriptor(registered)).toBeNull();
		expectBuilderError(() => builder.markRegistered(10_000, 13_000), /not allowed in package state 'registered'/);
	});

	it('rejects structural mistakes loudly', () => {
		const builder = freshBuilder();
		expectBuilderError(() => builder.confirmSegment(99, OBSERVED, 1, 2), /no segment with seq 99/);
		const b2 = freshBuilder();
		const seq = b2.openSegment(0, 1_000);
		expectBuilderError(() => b2.confirmSegment(seq, OBSERVED, -1, 2), /not after its start/);
	});
});

describe('descriptor truth rules', () => {
	it('rejects wrong schema, bad policy modes, and upload claims', () => {
		const descriptor = {
			...freshBuilder().snapshot(0),
			schema: 'other-v1',
		} as unknown as LocalPackageDescriptor;
		expect(validateDescriptor(descriptor)).toMatch(/schema/);
		const badPolicy = {
			...freshBuilder().snapshot(0),
			policyMode: 'server_default',
		} as unknown as LocalPackageDescriptor;
		expect(validateDescriptor(badPolicy)).toMatch(/unknown policy mode/);
		const uploadClaim = {
			...freshBuilder().snapshot(0),
			uploadedToDrive: true,
		} as unknown as LocalPackageDescriptor;
		expect(validateDescriptor(uploadClaim)).toMatch(/upload path that does not exist/);
	});

	it('binds end times and registration claims to package states', () => {
		const withEnd = {
			...freshBuilder().snapshot(0),
			endedAtUnixMs: 2_000, // after startedAt 1_000, but the package is still recording
		} as LocalPackageDescriptor;
		expect(validateDescriptor(withEnd)).toMatch(/recording descriptor cannot carry an end time/);

		const builder = freshBuilder();
		const seq = builder.openSegment(0, 1_000);
		builder.confirmSegment(seq, OBSERVED, 10_000, 11_000);
		const finalized = builder.finalize(10_000, 11_000);
		expect(validateDescriptor({ ...finalized, registeredAtUnixMs: 12_000 })).toMatch(/claims registration/);
		expect(validateDescriptor({ ...finalized, endedAtUnixMs: null })).toMatch(/must carry its end time/);
		expect(validateDescriptor({ ...finalized, startedAtUnixMs: 20_000 })).toMatch(/ends before it starts/);
	});

	it('fails closed on overlapping verified media and duplicate seqs', () => {
		const overlapping: LocalPackageDescriptor = {
			...freshBuilder().snapshot(0),
			segments: [verifiedSegment(1), verifiedSegment(2, { interval: { startMs: 5_000, endMs: 25_000 } })],
		};
		expect(validateDescriptor(overlapping)).toMatch(/duplicate media fails closed/);
		const duplicate: LocalPackageDescriptor = {
			...freshBuilder().snapshot(0),
			segments: [verifiedSegment(1), verifiedSegment(1)],
		};
		expect(validateDescriptor(duplicate)).toMatch(/duplicate segment seq/);
	});

	it('enforces the server-mirrored segment cap', () => {
		const segments = Array.from({ length: MAX_LOCAL_SEGMENTS + 1 }, (_, i) => verifiedSegment(i + 1));
		const overCap = { ...freshBuilder().snapshot(0), segments } as LocalPackageDescriptor;
		expect(validateDescriptor(overCap)).toMatch(/over the 10000 cap/);
		const builder = freshBuilder();
		expectBuilderError(
			() => {
				for (let i = 0; i <= MAX_LOCAL_SEGMENTS; i++) builder.openSegment(i, 1_000 + i);
			},
			/segment cap/,
		);
	});
});

describe('canonical JSON + digest', () => {
	it('is deterministic across key insertion order', () => {
		expect(canonicalJson({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } })).toBe(
			canonicalJson({ a: { c: [3, { y: 2, z: 1 }], d: 2 }, b: 1 }),
		);
	});

	it('digest pins everything except the digest field (Seal genre)', () => {
		const builder = freshBuilder();
		const seq = builder.openSegment(0, 1_000);
		builder.confirmSegment(seq, OBSERVED, 10_000, 11_000);
		const descriptor = builder.finalize(10_000, 11_000);
		expect(descriptor.integrityDigest).toBe(descriptorDigest({ ...descriptor, integrityDigest: null }));
		const tampered: LocalPackageDescriptor = {
			...descriptor,
			segments: descriptor.segments.map((s) => ({ ...s, byteSize: (s.byteSize ?? 0) + 1 })),
		};
		expect(descriptorDigest(tampered)).not.toBe(descriptor.integrityDigest);
	});
});

describe('computeCoverage', () => {
	it('merges adjacent verified runs and leaves every hole a listed gap', () => {
		const segments = [
			verifiedSegment(1, { interval: { startMs: 0, endMs: 10_000 } }),
			verifiedSegment(2, { interval: { startMs: 10_000, endMs: 20_000 } }), // adjacent → merge
			verifiedSegment(3, {
				interval: { startMs: 30_000, endMs: 40_000 },
				state: 'interrupted',
				mimeType: null,
				codec: null,
				container: null,
				byteSize: 10,
				interruptReason: 'crash',
			}), // never contributes
		];
		const coverage = computeCoverage(segments, 45_000);
		expect(coverage.available).toEqual([{ startMs: 0, endMs: 20_000 }]);
		expect(coverage.gaps).toEqual([
			{ startMs: 20_000, endMs: 45_000 },
		]);
	});

	it('reports the whole window as a gap when nothing verified', () => {
		expect(computeCoverage([], 30_000).gaps).toEqual([{ startMs: 0, endMs: 30_000 }]);
		expect(computeCoverage([], 30_000).available).toEqual([]);
	});
});

describe('cross-language seal KAT (the Go localcapture_test.go pin)', () => {
	// The EXACT known-answer fixture the Go KAT pins
	// (mailserver/internal/meet/localcapture_test.go's descriptorFixtureJSON,
	// values copied verbatim): a verified segment plus a truthful interrupted
	// one over [0,1500). The seal pin is TWO-SIDED: the Go
	// verifyDescriptorDigest leg and THIS assertion pin the SAME constant, so
	// a drift on either plane fails a test there.
	const GO_KAT_DIGEST = '969f4e1d930f4fcb4bb64260bc831bbe9c77799feb97b1262cae6fe432b7fe10';
	const goKatDescriptor = {
		schema: 'sjrec-local-v1',
		meetingId: 5,
		recordingId: null,
		packageState: 'finalized',
		captureMode: 'local_registered',
		policyMode: 'local_only',
		surfaces: ['microphone'],
		producer: { platform: 'darwin', platformVersion: '24.0.0', captureApiVersion: 'electron-1+chromium-2' },
		startedAtUnixMs: 500,
		endedAtUnixMs: 1500,
		registeredAtUnixMs: null,
		segments: [
			{
				seq: 1,
				state: 'verified',
				contentSha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
				byteSize: 100,
				mimeType: 'audio/webm',
				codec: 'opus',
				container: 'webm',
				interval: { startMs: 0, endMs: 1000 },
				wallStartUnixMs: 500,
				wallEndUnixMs: 1500,
				interruptReason: null,
			},
			{
				seq: 2,
				state: 'interrupted',
				contentSha256: null,
				byteSize: null,
				mimeType: null,
				codec: null,
				container: null,
				interval: { startMs: 1000, endMs: 1500 },
				wallStartUnixMs: 1500,
				wallEndUnixMs: 1800,
				interruptReason: 'device_stopped',
			},
		],
		uploadedToDrive: false,
		coverage: { available: [{ startMs: 0, endMs: 1000 }], gaps: [{ startMs: 1000, endMs: 1500 }] },
		integrityDigest: GO_KAT_DIGEST,
	} as unknown as LocalPackageDescriptor;

	it('reproduces the shared known-answer digest for the Go fixture', () => {
		// descriptorDigest clears integrityDigest itself — the same Seal genre
		// the Go verifier re-derives over the identical fixture bytes.
		expect(descriptorDigest(goKatDescriptor)).toBe(GO_KAT_DIGEST);
	});

	it('the KAT fixture is itself a truthful sealed descriptor', () => {
		expect(validateDescriptor(goKatDescriptor)).toBeNull();
	});
});
