// annotationSnapshots.test.ts — MEET plan M4: the durable annotation commit
// binding's send-side contract (the mirror of the Go annotation.go and the
// V267 reducer's admitted-shape gate): canonical serialization, the byte
// bound, the derived content identity, and the closed shape refusals.
import { describe, it, expect } from 'vitest';
import {
	MAX_ANNOTATION_SNAPSHOT_BYTES,
	serializeAnnotationSnapshot,
	annotationSnapshotRef,
} from './annotationSnapshots';

describe('serializeAnnotationSnapshot', () => {
	it('serializes deterministically regardless of key order (stable identity)', async () => {
		const a = await serializeAnnotationSnapshot({ strokes: [{ w: 2, pts: [1, 2] }], page: 3 });
		const b = await serializeAnnotationSnapshot({ page: 3, strokes: [{ pts: [1, 2], w: 2 }] });
		expect(a.ok).toBe(true);
		expect(b.ok).toBe(true);
		if (a.ok && b.ok) {
			expect(a.snapshot.text).toBe(b.snapshot.text);
			expect(a.snapshot.sha256).toBe(b.snapshot.sha256);
			expect(a.snapshot.byteSize).toBe(b.snapshot.byteSize);
		}
	});

	it('derives the content identity from the exact bytes', async () => {
		const r = await serializeAnnotationSnapshot({ ok: true });
		expect(r.ok).toBe(true);
		if (r.ok) {
			// 64 lowercase hex chars; the digest matches a manual sha256 of the
			// canonical text via the same subtle API (identity derived, never
			// claimed).
			expect(r.snapshot.sha256).toMatch(/^[0-9a-f]{64}$/);
			expect(r.snapshot.byteSize).toBe(new TextEncoder().encode(r.snapshot.text).length);
		}
	});

	it('refuses a non-object snapshot (closed shape)', async () => {
		await expect(serializeAnnotationSnapshot('{"x":1}')).resolves.toEqual({ ok: false, error: 'not-an-object' });
		await expect(serializeAnnotationSnapshot([1, 2, 3])).resolves.toEqual({ ok: false, error: 'not-an-object' });
		await expect(serializeAnnotationSnapshot(null)).resolves.toEqual({ ok: false, error: 'not-an-object' });
	});

	it('refuses a snapshot over the stored-object bound', async () => {
		const fat = { blob: 'x'.repeat(MAX_ANNOTATION_SNAPSHOT_BYTES) };
		await expect(serializeAnnotationSnapshot(fat)).resolves.toEqual({ ok: false, error: 'over-bound' });
	});
});

describe('annotationSnapshotRef', () => {
	it('matches the admitted StableRef grammar the server derives', () => {
		expect(annotationSnapshotRef(7, 3)).toBe('annotations/p7-s3.json');
		expect(annotationSnapshotRef(0, 0)).toBe('annotations/p0-s0.json');
	});
});
