import { beforeEach, describe, it, expect } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import MessageCard from './MessageCard.svelte';
import type { Email } from '$lib/types/jmap';
import { jmapSession } from '$lib/stores/session';

// U3 Item A: tracker-image detection + count + load-but-strip banner.

function makeEmail(bodyHTML: string): Email {
	return {
		id: 'e1',
		threadId: 't1',
		mailboxIds: { mb1: true },
		from: [{ name: 'Sender', email: 'sender@example.com' }],
		to: [{ name: 'Me', email: 'me@setjoin.local' }],
		subject: 'Newsletter',
		preview: 'Preview',
		bodyHTML,
		receivedAt: '2026-07-01T10:00:00Z',
		keywords: { $seen: true },
	};
}

function noop() {}

function setExternalLabels(enabled: boolean) {
	jmapSession.set({
		effectiveCapabilities: {
			apps: {},
			features: { assist: false, bundles: false, external_labels: enabled },
		},
	} as never);
}

beforeEach(() => {
	jmapSession.set(null);
});

describe('MessageCard external identity label', () => {
	it('labels an external sender in the expanded identity block and keeps the warning banner', () => {
		setExternalLabels(true);
		const email = { ...makeEmail('<p>hi</p>'), isExternal: true };
		const { getByText } = render(MessageCard, {
			email,
			expanded: true,
			onToggle: noop,
			onReply: noop,
			onForward: noop,
		});

		expect(getByText('External')).toBeTruthy();
		expect(getByText('This message is from an external sender.')).toBeTruthy();
	});

	it('labels an external sender in the collapsed thread summary', () => {
		setExternalLabels(true);
		const email = { ...makeEmail('<p>hi</p>'), isExternal: true };
		const { getByText } = render(MessageCard, {
			email,
			expanded: false,
			onToggle: noop,
			onReply: noop,
			onForward: noop,
		});

		expect(getByText('External')).toBeTruthy();
	});

	it('hides both the identity label and external banner when the capability is off', () => {
		setExternalLabels(false);
		const email = { ...makeEmail('<p>hi</p>'), isExternal: true };
		const { queryByText } = render(MessageCard, {
			email,
			expanded: true,
			onToggle: noop,
			onReply: noop,
			onForward: noop,
		});

		expect(queryByText('External')).toBeNull();
		expect(queryByText('This message is from an external sender.')).toBeNull();
	});
});

describe('MessageCard tracker banner (U3 Item A)', () => {
	it('shows "N trackers blocked" plus an escape hatch when the body carries a tracker pixel', async () => {
		const email = makeEmail('<img src="https://sendgrid.net/open.gif" width="1" height="1"><p>hi</p>');
		const { getByText, findByText } = render(MessageCard, {
			email,
			expanded: true,
			onToggle: noop,
			onReply: noop,
			onForward: noop,
		});

		await fireEvent.click(getByText('Show HTML'));

		expect(await findByText(/1 tracker blocked/)).toBeTruthy();
		expect(await findByText('Load all images anyway')).toBeTruthy();
	});

	it('the escape hatch removes itself once clicked (per-message opt-in, not global)', async () => {
		const email = makeEmail('<img src="https://sendgrid.net/open.gif" width="1" height="1">');
		const { getByText, findByText, queryByText } = render(MessageCard, {
			email,
			expanded: true,
			onToggle: noop,
			onReply: noop,
			onForward: noop,
		});

		await fireEvent.click(getByText('Show HTML'));
		await findByText('Load all images anyway');
		await fireEvent.click(getByText('Load all images anyway'));

		expect(queryByText('Load all images anyway')).toBeNull();
	});

	it('shows no tracker banner for a body with only regular images', async () => {
		const email = makeEmail('<img src="https://example.com/photo.jpg"><p>hi</p>');
		const { getByText, queryByText } = render(MessageCard, {
			email,
			expanded: true,
			onToggle: noop,
			onReply: noop,
			onForward: noop,
		});

		await fireEvent.click(getByText('Show HTML'));

		expect(queryByText(/tracker/i)).toBeNull();
	});
});
