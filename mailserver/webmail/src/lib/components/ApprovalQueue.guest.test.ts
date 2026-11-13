import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import ApprovalQueue from './ApprovalQueue.svelte';
import type { ApprovalRequest } from '$lib/types/approvals';

describe('ApprovalQueue guest invite response shape', () => {
	it('labels guest invites and renders safe requester and invited-email evidence from payload', () => {
		// Exact list response shape: the API does not return requesterName or
		// requesterEmail; guest review evidence is carried in safe payload fields.
		const guestInvite = {
			id: 71,
			consumerType: 'guest.invite',
			subject: 'Invite guest invited@example.net',
			status: 'pending',
			requesterUserId: 19,
			approverKind: 'user',
			approverRef: 44,
			createdAt: new Date().toISOString(),
			expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
			payload: {
				requester_name: 'Alice Requester',
				invited_email: 'invited@example.net',
			},
		} satisfies ApprovalRequest;

		render(ApprovalQueue, {
			pendingItems: [guestInvite],
			myRequests: [],
			selectedId: null,
			tab: 'pending',
			loading: false,
			error: '',
			currentUserEmail: 'approver@example.test',
			onSelect: vi.fn(),
			onTabChange: vi.fn(),
			onRetry: vi.fn(),
		});

		expect(screen.getByText('Guest invitation')).toBeInTheDocument();
		expect(screen.getByText('Alice Requester')).toBeInTheDocument();
		expect(screen.getByText('invited@example.net')).toBeInTheDocument();
		expect(screen.queryByText('Group Mail')).toBeNull();
	});
});
