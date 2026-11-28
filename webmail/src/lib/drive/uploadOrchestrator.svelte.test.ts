import { describe, it, expect, vi, beforeEach } from 'vitest';
import { UploadOrchestrator, uploadOrchestrator, uploadErrorMessage } from './uploadOrchestrator.svelte';
import { DriveError, type PutVersionResult } from './api';

const uploadFile = vi.fn();

vi.mock('./upload', async () => {
	const actual = await vi.importActual<typeof import('./upload')>('./upload');
	return {
		...actual,
		uploadFile: (...a: unknown[]) => uploadFile(...a),
	};
});

function file(name: string, size = 100): File {
	return new File([new Uint8Array(size)], name);
}

const RESULT: PutVersionResult = { versionId: 1, conflict: false, branchId: null, headVersionId: 1, wormPending: false };

describe('UploadOrchestrator', () => {
	beforeEach(() => {
		uploadFile.mockReset();
	});

	it('start() pushes a progress entry with status uploading', async () => {
		let resolveUpload: (v: PutVersionResult) => void = () => {};
		uploadFile.mockImplementationOnce(() => new Promise((resolve) => (resolveUpload = resolve)));
		const orch = new UploadOrchestrator();
		const f = file('report.docx', 500);

		const started = orch.start(1, 42, f, { baseVersionId: null, contentType: 'text/plain' });
		expect(orch.uploads).toHaveLength(1);
		expect(orch.uploads[0]).toMatchObject({ name: 'report.docx', sent: 0, total: 500, status: 'uploading' });

		resolveUpload(RESULT);
		await started;
	});

	it('the progress callback updates the matching entry (reactive uploads array)', async () => {
		let capturedOnProgress: ((sent: number, total: number) => void) | undefined;
		uploadFile.mockImplementationOnce((_s: number, _n: number, _f: File, opts: { onProgress?: (s: number, t: number) => void }) => {
			capturedOnProgress = opts.onProgress;
			return Promise.resolve(RESULT);
		});
		const orch = new UploadOrchestrator();
		await orch.start(1, 42, file('a.bin', 1000), { baseVersionId: null });

		capturedOnProgress?.(500, 1000);
		expect(orch.uploads[0].sent).toBe(500);
	});

	it('transitions to done on success and returns the result', async () => {
		uploadFile.mockResolvedValueOnce(RESULT);
		const orch = new UploadOrchestrator();

		const outcome = await orch.start(1, 42, file('a.bin'), { baseVersionId: null });

		expect(outcome).toEqual({ ok: true, id: orch.uploads[0].id, result: RESULT });
		expect(orch.uploads[0].status).toBe('done');
	});

	it('transitions to error on a thrown upload, with a mapped errorMessage', async () => {
		const err = new DriveError({ status: 409, code: 'BZ148', detail: 'quota' });
		uploadFile.mockRejectedValueOnce(err);
		const orch = new UploadOrchestrator();

		const outcome = await orch.start(1, 42, file('a.bin'), { baseVersionId: null });

		expect(outcome.ok).toBe(false);
		expect(orch.uploads[0].status).toBe('error');
		expect(orch.uploads[0].errorMessage).toBe(uploadErrorMessage(err));
	});

	it('remove() drops the entry by id', async () => {
		uploadFile.mockResolvedValueOnce(RESULT);
		const orch = new UploadOrchestrator();
		const outcome = await orch.start(1, 42, file('a.bin'), { baseVersionId: null });

		orch.remove(outcome.id);

		expect(orch.uploads).toHaveLength(0);
	});

	it('exports a shared singleton instance', () => {
		expect(uploadOrchestrator).toBeInstanceOf(UploadOrchestrator);
	});
});

describe('uploadErrorMessage', () => {
	it('maps BZ148 to the quota-specific message, falling back for other codes', () => {
		const quota = new DriveError({ status: 409, code: 'BZ148', detail: 'quota' });
		const other = new DriveError({ status: 500, code: 'BZ999', detail: 'weird' });
		expect(uploadErrorMessage(quota)).not.toBe(uploadErrorMessage(other));
	});
});
