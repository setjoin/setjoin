import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import type { EmailNudge } from '$lib/types/jmap';

// NudgeBanner self-fetches via the JMAP client wrapper — mock both calls.
vi.mock('$lib/jmap/client', () => ({
	emailNudges: vi.fn(),
	emailNudgeDismiss: vi.fn(),
}));

import NudgeBanner from './NudgeBanner.svelte';
import { emailNudges, emailNudgeDismiss } from '$lib/jmap/client';

const NUDGES: EmailNudge[] = [
	{
		threadId: 'thread-A',
		emailId: 'e-A',
		subject: 'Please review',
		counterpart: 'boss@corp.example',
		kind: 'stale_unanswered',
		lastActivityAt: '2026-07-01T10:00:00Z',
	},
	{
		threadId: 'thread-B',
		emailId: 'e-B',
		subject: 'Following up',
		counterpart: 'client@ext.example',
		kind: 'no_reply_sent',
		lastActivityAt: '2026-07-01T09:00:00Z',
	},
];

describe('NudgeBanner (#13)', () => {
	beforeEach(() => {
		vi.mocked(emailNudges).mockReset();
		vi.mocked(emailNudgeDismiss).mockReset();
		vi.mocked(emailNudgeDismiss).mockResolvedValue(undefined);
	});

	it('renders kind-specific copy for both finding types', async () => {
		vi.mocked(emailNudges).mockResolvedValue(NUDGES);
		const { findByText } = render(NudgeBanner, {});

		// stale_unanswered copy names the sender who is waiting.
		expect(await findByText(/boss@corp.example is waiting/)).toBeTruthy();
		// no_reply_sent copy names the recipient we sent to.
		expect(await findByText(/Sent to client@ext.example/)).toBeTruthy();
	});

	it('dismiss removes the row and calls emailNudgeDismiss with the threadId', async () => {
		vi.mocked(emailNudges).mockResolvedValue(NUDGES);
		const { findAllByRole, queryByText } = render(NudgeBanner, {});

		const dismissButtons = await findAllByRole('button', { name: 'Dismiss' });
		expect(dismissButtons).toHaveLength(2);
		await fireEvent.click(dismissButtons[0]); // thread-A (first nudge)

		expect(emailNudgeDismiss).toHaveBeenCalledWith('thread-A');
		await waitFor(() => expect(queryByText(/boss@corp.example is waiting/)).toBeNull());
	});

	it('renders nothing when the nudge list is empty (toggle off)', async () => {
		vi.mocked(emailNudges).mockResolvedValue([]);
		const { container } = render(NudgeBanner, {});
		await waitFor(() => expect(container.querySelector('.nudge-banner')).toBeNull());
	});
});
