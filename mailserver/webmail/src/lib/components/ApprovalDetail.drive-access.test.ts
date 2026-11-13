import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import ApprovalDetail from './ApprovalDetail.svelte';
import type { ApprovalRequest } from '$lib/types/approvals';

const request: ApprovalRequest = {
	id: 90, consumerType: 'drive.access', requesterUserId: 4, requesterName: 'Rae Requester',
	subject: 'Drive access request 12', status: 'pending', approverKind: 'user', approverRef: 2,
	createdAt: '2026-08-03T10:00:00Z', expiresAt: '2026-08-04T10:00:00Z',
	payload: {
		nodeId: '12', spaceId: '7', requestedCapabilities: ['preview', 'download'],
		requestedPropagation: 'subtree', requestedExpiresAt: '2026-08-04T08:00:00Z',
		requestedMaxUses: 10, emergency: false, reason: 'Quarterly audit evidence', expectedEpoch: '8', grantId: null,
	},
};

describe('ApprovalDetail Drive access', () => {
	it('submits only the approver-selected narrowing plus the fresh epoch', async () => {
		const onApprove = vi.fn();
		render(ApprovalDetail, { request, deciding: null, decideError: '', decideSuccess: '', comment: '', tab: 'pending', onCommentChange: vi.fn(), onApprove, onDeny: vi.fn(), onCancel: vi.fn(), onBack: vi.fn() });
		expect(screen.getByText('Quarterly audit evidence')).toBeTruthy();
		await fireEvent.click(screen.getByLabelText('Preview'));
		await fireEvent.change(screen.getByLabelText('Scope'), { target: { value: 'self' } });
		await fireEvent.input(screen.getByLabelText('Maximum uses'), { target: { value: '3' } });
		await fireEvent.click(screen.getByRole('button', { name: /Approve:/ }));
		expect(onApprove).toHaveBeenCalledWith(expect.objectContaining({ capabilities: ['download'], propagation: 'self', maxUses: 3, expectedEpoch: '8' }));
	});

	it('disables approval when every requested capability is removed', async () => {
		render(ApprovalDetail, { request, deciding: null, decideError: '', decideSuccess: '', comment: '', tab: 'pending', onCommentChange: vi.fn(), onApprove: vi.fn(), onDeny: vi.fn(), onCancel: vi.fn(), onBack: vi.fn() });
		await fireEvent.click(screen.getByLabelText('Preview'));
		await fireEvent.click(screen.getByLabelText('Download'));
		expect(screen.getByRole('button', { name: /Approve:/ })).toBeDisabled();
	});
});
