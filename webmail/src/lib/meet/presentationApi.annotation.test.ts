// presentationApi.annotation.test.ts — MEET plan M4: the annotation commit
// and semantic read transports (the standalone M4 functions in
// presentationApi.ts), against a stubbed global fetch: the exact wire shapes
// (clear vs snapshot commit bodies, the read paths) and the decoded
// responses.
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
	commitAnnotation,
	fetchAnnotationSnapshot,
	fetchSemanticPackage,
	fetchSemanticReplay,
} from './presentationApi';
import type { SerializedAnnotationSnapshot } from './annotationSnapshots';

const snapshot: SerializedAnnotationSnapshot = {
	text: '{"strokes":[[1,2,3,4]]}',
	sha256: 'ab'.repeat(32),
	byteSize: 21,
};

function stubFetch(body: unknown): ReturnType<typeof vi.fn> {
	const mock = vi.fn().mockResolvedValue({
		ok: true,
		status: 200,
		json: async () => body,
	} as Response);
	vi.stubGlobal('fetch', mock);
	return mock;
}

afterEach(() => vi.unstubAllGlobals());

describe('commitAnnotation', () => {
	it('POSTs the snapshot commit with the exact serialized text', async () => {
		const mock = stubFetch({
			presentationId: 7,
			status: 'ACTIVE',
			checkpointSeq: 3,
			presenterGeneration: 1,
			pageIndex: 0,
			manifestGeneration: 1,
			annotation: { snapshotRef: 'annotations/p7-s3.json', sha256: snapshot.sha256, byteSize: snapshot.byteSize },
		});
		const out = await commitAnnotation(5, 7, {
			presenterGeneration: 1,
			checkpointSeq: 2,
			clear: false,
			snapshot,
		});
		expect(mock).toHaveBeenCalledWith(
			'/api/meet/5/presentation/7/annotation',
			expect.objectContaining({ method: 'POST' }),
		);
		const body = JSON.parse((mock.mock.calls[0] as unknown as [string, { body: string }])[1].body);
		expect(body).toEqual({ presenterGeneration: 1, checkpointSeq: 2, snapshot: snapshot.text });
		expect(out.annotation?.snapshotRef).toBe('annotations/p7-s3.json');
	});

	it('POSTs a clear without snapshot fields', async () => {
		const mock = stubFetch({
			presentationId: 7,
			status: 'ACTIVE',
			checkpointSeq: 4,
			presenterGeneration: 1,
			pageIndex: 0,
			manifestGeneration: 1,
		});
		await commitAnnotation(5, 7, { presenterGeneration: 1, checkpointSeq: 3, clear: true });
		const body = JSON.parse((mock.mock.calls[0] as unknown as [string, { body: string }])[1].body);
		expect(body).toEqual({ presenterGeneration: 1, checkpointSeq: 3, clear: true });
		expect(body.snapshot).toBeUndefined();
	});
});

describe('the authorized reads', () => {
	it('fetchAnnotationSnapshot hits the bounded read path', async () => {
		const mock = stubFetch({
			presentationId: 7,
			snapshot: {
				snapshotRef: 'annotations/p7-s3.json',
				sha256: snapshot.sha256,
				byteSize: snapshot.byteSize,
				checkpointSeq: 3,
				presenterGeneration: 1,
				content: snapshot.text,
				createdAt: '2026-09-18T00:00:00Z',
			},
		});
		const out = await fetchAnnotationSnapshot(5, 7);
		expect(mock).toHaveBeenCalledWith('/api/meet/5/presentation/7/annotation', expect.anything());
		expect(out.snapshot?.content).toBe(snapshot.text);
	});

	it('fetchSemanticPackage and fetchSemanticReplay hit the M4 read routes', async () => {
		const pkg = { recordingId: 9, meetingId: 5, packageState: 'ACTIVE', segments: [], children: [], exports: [] };
		const mock = stubFetch(pkg);
		const out = await fetchSemanticPackage(5, 9);
		expect(mock).toHaveBeenCalledWith('/api/meet/5/semantic/9/package', expect.anything());
		expect(out.recordingId).toBe(9);
		const outReplay = await fetchSemanticReplay(5, 9);
		expect(mock).toHaveBeenCalledWith('/api/meet/5/semantic/9/replay', expect.anything());
		expect(outReplay.recordingId).toBe(9);
	});
});
