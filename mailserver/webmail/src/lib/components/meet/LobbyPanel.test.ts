// LobbyPanel.test.ts — Meet B1 Task 16 named tests: admit calls decideRequest
// and removes the row; the guestAllowed toggle calls the settings route.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import LobbyPanel from './LobbyPanel.svelte';
import { MeetError } from '$lib/meet/api';
import { toasts, clearToasts } from '$lib/components/ui';

const decideRequest = vi.fn();
const setGuestAllowed = vi.fn();
vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return {
		...actual,
		decideRequest: (...a: unknown[]) => decideRequest(...a),
		setGuestAllowed: (...a: unknown[]) => setGuestAllowed(...a),
	};
});

afterEach(() => vi.clearAllMocks());

const REQ = { requestId: 7, displayName: 'Alice', isMemberKnock: false, createdAt: '', expiresAt: '' };

describe('LobbyPanel', () => {
	it('admit calls decideRequest(meetingId, requestId, "admit") and removes the row', async () => {
		decideRequest.mockResolvedValue(undefined);
		render(LobbyPanel, { meetingId: 42, pendingRequests: [REQ], guestAllowed: false });
		expect(screen.getByTestId('knock-7')).toBeTruthy();

		await fireEvent.click(screen.getByText('Admit'));
		expect(decideRequest).toHaveBeenCalledWith(42, 7, 'admit');
		await vi.waitFor(() => expect(screen.queryByTestId('knock-7')).toBeNull());
	});

	it('the guestAllowed toggle calls the settings route with the flipped value', async () => {
		setGuestAllowed.mockResolvedValue(undefined);
		render(LobbyPanel, { meetingId: 42, pendingRequests: [], guestAllowed: false });
		await fireEvent.click(screen.getByRole('switch'));
		expect(setGuestAllowed).toHaveBeenCalledWith(42, true);
	});

	// D-3 (Meet B2 Task 10): an admit whose rejection is BZ199 toasts and
	// restores the row; every other error keeps the existing silent restore.
	it('a BZ199 admit rejection toasts admitBlocked AND restores the row', async () => {
		decideRequest.mockRejectedValue(new MeetError({ status: 403, code: 'BZ199', detail: 'recording in progress' }));
		render(LobbyPanel, { meetingId: 42, pendingRequests: [REQ], guestAllowed: false });

		await fireEvent.click(screen.getByText('Admit'));
		await vi.waitFor(() => expect(screen.getByTestId('knock-7')).toBeTruthy());
		await vi.waitFor(() =>
			expect(toasts.some((t) => t.message === 'A recording is in progress. Stop the recording to admit guests.')).toBe(
				true,
			),
		);
	});

	it('a non-BZ199 admit error restores the row silently — no toast', async () => {
		clearToasts();
		decideRequest.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'internal error' }));
		render(LobbyPanel, { meetingId: 42, pendingRequests: [REQ], guestAllowed: false });

		await fireEvent.click(screen.getByText('Admit'));
		await vi.waitFor(() => expect(screen.getByTestId('knock-7')).toBeTruthy());
		expect(toasts.length).toBe(0);
	});

	// UX #9 (whole-pipeline review): LobbyPanel joined the sidePanel exclusive
	// slot (was unconditionally docked) — the MeetChatPanel close-button
	// precedent, needed since it can now be a full-screen mobile overlay.
	it('renders a close button when onClose is provided, and none otherwise', () => {
		const onClose = vi.fn();
		const { unmount } = render(LobbyPanel, { meetingId: 42, pendingRequests: [], guestAllowed: false, onClose });
		expect(screen.getByLabelText('Close')).toBeTruthy();
		unmount();

		render(LobbyPanel, { meetingId: 42, pendingRequests: [], guestAllowed: false });
		expect(screen.queryByLabelText('Close')).toBeNull();
	});

	it('clicking the close button calls onClose', async () => {
		const onClose = vi.fn();
		render(LobbyPanel, { meetingId: 42, pendingRequests: [], guestAllowed: false, onClose });
		await fireEvent.click(screen.getByLabelText('Close'));
		expect(onClose).toHaveBeenCalledOnce();
	});
});
