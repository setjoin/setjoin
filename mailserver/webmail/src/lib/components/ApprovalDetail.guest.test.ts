import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import ApprovalDetail from './ApprovalDetail.svelte';

describe('ApprovalDetail guest invite evidence', () => {
	it('renders only the safe guest-invite evidence payload', () => {
		render(ApprovalDetail, { request: {
			id: 1, consumerType: 'guest.invite', requesterName: 'Rae Requester', requesterEmail: 'rae@example.test',
			subject: 'Invite guest@example.net', status: 'pending', approverKind: 'user', approverRef: 2,
			createdAt: new Date().toISOString(), expiresAt: new Date(Date.now()+60_000).toISOString(),
			payload: { invited_email: 'guest@example.net', requester_name: 'Rae Requester', message: 'For the launch' },
		}, deciding: null, decideError: '', decideSuccess: '', comment: '', tab: 'pending',
		onCommentChange: vi.fn(), onApprove: vi.fn(), onDeny: vi.fn(), onCancel: vi.fn(), onBack: vi.fn() });
		expect(screen.getByText('guest@example.net')).toBeTruthy();
		expect(screen.getAllByText('Rae Requester')).toHaveLength(2);
		expect(screen.getByText('For the launch')).toBeTruthy();
	});
});
