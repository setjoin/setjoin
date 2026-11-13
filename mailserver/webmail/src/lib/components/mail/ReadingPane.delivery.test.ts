import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ReadingPane from './ReadingPane.svelte';
import type { Email } from '$lib/types/jmap';

// Mock the delivery API so the panel doesn't make real HTTP calls.
vi.mock('$lib/api/delivery', () => ({
	messageTrace: vi.fn().mockResolvedValue({
		direction: 'inbound',
		hopCount: 2,
		totalTransitMs: 1200,
		slowestHopIndex: null,
		hops: [
			{
				index: 0,
				fromHost: 'smtp.sender.com',
				byHost: 'mx.setjoin.local',
				timestamp: '2026-06-21T10:00:00Z',
				delayMs: 600,
				tlsActive: true,
				isOurInfra: false,
				parseOk: true,
			},
			{
				index: 1,
				fromHost: 'mx.setjoin.local',
				byHost: 'inbox.setjoin.local',
				timestamp: '2026-06-21T10:00:01Z',
				delayMs: 600,
				tlsActive: true,
				isOurInfra: true,
				parseOk: true,
			},
		],
		auth: {
			spf: { result: 'pass', domain: 'sender.com' },
			dkim: { result: 'pass', domain: 'sender.com' },
			dmarc: { result: 'pass', domain: 'sender.com' },
		},
	}),
}));

function makeEmail(overrides: Partial<Email> = {}): Email {
	return {
		id: 'e42',
		threadId: 't42',
		mailboxIds: { mb1: true },
		from: [{ name: 'Bob Jones', email: 'bob@example.com' }],
		to: [{ name: 'Me', email: 'me@setjoin.local' }],
		subject: 'Delivery test email',
		preview: 'Preview',
		bodyText: 'Body text here.',
		receivedAt: '2026-06-21T09:00:00Z',
		keywords: { $seen: true },
		...overrides,
	};
}

const baseHandlers = {
	mailboxes: [],
	currentRole: null,
	actions: {
		onArchive: vi.fn(),
		onSnooze: vi.fn(),
		onTrash: vi.fn(),
		onMute: vi.fn(),
		onStar: vi.fn(),
		onReply: vi.fn(),
		onForward: vi.fn(),
		onRemoveTag: vi.fn(),
		onAddTag: vi.fn(),
		onCreateTag: vi.fn(),
		onSendReply: vi.fn(),
		onScheduleReply: vi.fn(),
	},
};

describe('ReadingPane — "Inspect delivery" overflow menu trigger', () => {
	it('renders a "More actions" menu trigger button', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			...baseHandlers,
		});
		const trigger = container.querySelector('[aria-label="More actions"]');
		expect(trigger).not.toBeNull();
	});

	it('opens a menu with an "Inspect delivery" item when "More actions" is clicked', async () => {
		const { container, getByText } = render(ReadingPane, {
			email: makeEmail(),
			...baseHandlers,
		});
		const trigger = container.querySelector('[aria-label="More actions"]') as HTMLButtonElement;
		expect(trigger).not.toBeNull();
		await fireEvent.click(trigger);

		const item = getByText('Inspect delivery');
		expect(item).not.toBeNull();
	});

	it('clicking "Inspect delivery" opens the DeliveryPanel dialog', async () => {
		const { container, getByText, getByRole } = render(ReadingPane, {
			email: makeEmail(),
			...baseHandlers,
		});
		// Open the overflow menu
		const trigger = container.querySelector('[aria-label="More actions"]') as HTMLButtonElement;
		await fireEvent.click(trigger);

		// Click the menu item
		const item = getByText('Inspect delivery');
		await fireEvent.click(item);

		// The DeliveryPanel should be mounted (role="dialog")
		await waitFor(() => {
			expect(getByRole('dialog')).not.toBeNull();
		});
	});

	it('the DeliveryPanel can be closed via its close button', async () => {
		const { container, getByText, getByRole, queryByRole } = render(ReadingPane, {
			email: makeEmail(),
			...baseHandlers,
		});
		// Open the overflow menu and click Inspect delivery
		const trigger = container.querySelector('[aria-label="More actions"]') as HTMLButtonElement;
		await fireEvent.click(trigger);
		await fireEvent.click(getByText('Inspect delivery'));

		// Wait for dialog
		await waitFor(() => expect(getByRole('dialog')).not.toBeNull());

		// Close the dialog via its close button
		const closeBtn = container.querySelector('[aria-label="Close"]') as HTMLButtonElement;
		expect(closeBtn).not.toBeNull();
		await fireEvent.click(closeBtn);

		await waitFor(() => {
			expect(queryByRole('dialog')).toBeNull();
		});
	});
});
