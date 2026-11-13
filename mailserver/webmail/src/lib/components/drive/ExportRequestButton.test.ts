import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import ExportRequestButton from './ExportRequestButton.svelte';
import { DriveError } from '$lib/drive/api';

const requestExport = vi.fn();
const exportDownloadUrl = vi.fn((token: string) => `/api/drive/export/${token}`);

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		requestExport: (...a: unknown[]) => requestExport(...a),
		exportDownloadUrl: (...a: [string]) => exportDownloadUrl(...a),
	};
});

describe('ExportRequestButton', () => {
	let assignSpy: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		requestExport.mockReset();
		exportDownloadUrl.mockClear();
		localStorage.clear();
		assignSpy = vi.fn();
		vi.stubGlobal('location', { ...window.location, assign: assignSpy });
		vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ myRequests: [] }), { status: 200 })));
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it('renders nothing for a regular-classification version (plain download link owns that case)', () => {
		render(ExportRequestButton, { versionId: 1, action: 'download', classification: 'regular' });
		expect(screen.queryByRole('button')).toBeNull();
	});

	it('granted immediately: navigates via window.location.assign, never renders an anchor', async () => {
		requestExport.mockResolvedValue({ status: 'granted', grantId: 5, token: 'plaintext-tok' });
		render(ExportRequestButton, { versionId: 1, action: 'download', classification: 'secure' });
		await fireEvent.click(screen.getByRole('button', { name: 'Request download' }));
		await vi.waitFor(() => expect(assignSpy).toHaveBeenCalledWith('/api/drive/export/plaintext-tok'));
		expect(document.querySelector('a[href*="plaintext-tok"]')).toBeNull();
	});

	it('pending: shows the pending status and persists the token to sessionStorage (session-scoped, never localStorage)', async () => {
		requestExport.mockResolvedValue({ status: 'pending', requestId: 42, token: 'ptok' });
		render(ExportRequestButton, { versionId: 9, action: 'download', classification: 'gxp' });
		await fireEvent.click(screen.getByRole('button', { name: 'Request download' }));
		await vi.waitFor(() => expect(screen.getByText('Approval pending — you will be notified')).toBeTruthy());
		const stored = JSON.parse(sessionStorage.getItem('drive.exportTokens') ?? '[]');
		expect(stored).toEqual([{ requestId: 42, token: 'ptok', versionId: 9, action: 'download' }]);
		// The bearer token must NOT outlive the browser session in localStorage.
		expect(localStorage.getItem('drive.exportTokens')).toBeNull();
	});

	it('BZ145 (WORM-pending) shows the blocked message, not a generic error', async () => {
		requestExport.mockRejectedValue(new DriveError({ status: 409, code: 'BZ145', detail: 'locked' }));
		render(ExportRequestButton, { versionId: 1, action: 'download', classification: 'gxp' });
		await fireEvent.click(screen.getByRole('button', { name: 'Request download' }));
		await vi.waitFor(() => expect(screen.getByText('Temporarily blocked: storage locks are being applied')).toBeTruthy());
	});

	it('resumes a pending request on mount from sessionStorage and polls approval status to approved, then downloads via window.location.assign on click', async () => {
		sessionStorage.setItem(
			'drive.exportTokens',
			JSON.stringify([{ requestId: 7, token: 'resumed-tok', versionId: 3, action: 'download' }]),
		);
		vi.stubGlobal(
			'fetch',
			vi.fn(async () =>
				new Response(JSON.stringify({ myRequests: [{ id: 7, status: 'applied' }] }), { status: 200 }),
			),
		);
		render(ExportRequestButton, { versionId: 3, action: 'download', classification: 'gxp' });
		await vi.waitFor(() => expect(screen.getByRole('button', { name: 'Download' })).toBeTruthy());

		await fireEvent.click(screen.getByRole('button', { name: 'Download' }));
		expect(assignSpy).toHaveBeenCalledWith('/api/drive/export/resumed-tok');
		expect(JSON.parse(sessionStorage.getItem('drive.exportTokens') ?? '[]')).toEqual([]);
	});

	it('a denied approval clears the persisted token and shows the denied state', async () => {
		sessionStorage.setItem(
			'drive.exportTokens',
			JSON.stringify([{ requestId: 8, token: 'tok8', versionId: 4, action: 'download' }]),
		);
		vi.stubGlobal(
			'fetch',
			vi.fn(async () =>
				new Response(JSON.stringify({ myRequests: [{ id: 8, status: 'denied' }] }), { status: 200 }),
			),
		);
		render(ExportRequestButton, { versionId: 4, action: 'download', classification: 'gxp' });
		await vi.waitFor(() => expect(screen.getByText('Request denied')).toBeTruthy());
		expect(JSON.parse(sessionStorage.getItem('drive.exportTokens') ?? '[]')).toEqual([]);
	});
});
