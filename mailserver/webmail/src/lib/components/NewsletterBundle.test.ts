import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import NewsletterBundle from './NewsletterBundle.svelte';

interface NewsletterSender {
	id: string;
	fromName: string;
	fromAddr: string;
	subject: string;
	count: number;
}

function makeSender(overrides: Partial<NewsletterSender> = {}): NewsletterSender {
	return {
		id: 'e1',
		fromName: 'ACME Newsletter',
		fromAddr: 'news@acme.example.com',
		subject: 'Your weekly digest',
		count: 42,
		...overrides,
	};
}

describe('NewsletterBundle', () => {
	it('renders the bundle header with total count', () => {
		const senders = [
			makeSender({ id: 'e1', fromName: 'ACME', count: 12 }),
			makeSender({ id: 'e2', fromName: 'BetaList', count: 5 }),
		];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: false,
		});
		// Header should show total count (12 + 5 = 17)
		expect(container.textContent).toContain('17');
		expect(container.textContent).toContain('Newsletters');
	});

	it('renders one sender row per bundle when expanded', () => {
		const senders = [
			makeSender({ id: 'e1', fromName: 'ACME', count: 3 }),
			makeSender({ id: 'e2', fromName: 'BetaList', count: 7 }),
		];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: true,
		});
		const rows = container.querySelectorAll('.sender-row');
		expect(rows.length).toBe(2);
		expect(container.textContent).toContain('ACME');
		expect(container.textContent).toContain('BetaList');
	});

	it('does not render sender rows when collapsed', () => {
		const senders = [makeSender()];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: false,
		});
		expect(container.querySelector('.sender-row')).toBeNull();
	});

	it('calls onselect with messageId when a sender row is clicked', async () => {
		const onselect = vi.fn();
		const senders = [makeSender({ id: 'e99' })];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: true,
			onselect,
		});
		const btn = container.querySelector('.sender-main') as HTMLElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onselect).toHaveBeenCalledTimes(1);
		expect(onselect).toHaveBeenCalledWith({ messageId: 'e99' });
	});

	it('calls onunsubscribe when unsubscribe button is clicked', async () => {
		const onunsubscribe = vi.fn();
		const senders = [makeSender({ fromAddr: 'spam@example.com' })];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: true,
			onunsubscribe,
		});
		const unsubBtn = container.querySelector('.unsub-btn') as HTMLElement;
		expect(unsubBtn).not.toBeNull();
		await fireEvent.click(unsubBtn);
		expect(onunsubscribe).toHaveBeenCalledTimes(1);
		expect(onunsubscribe).toHaveBeenCalledWith({ senderAddr: 'spam@example.com' });
	});

	it('renders sender avatar initials in the header', () => {
		const senders = [
			makeSender({ id: 'e1', fromName: 'Alice' }),
			makeSender({ id: 'e2', fromName: 'Bob' }),
			makeSender({ id: 'e3', fromName: 'Carol' }),
		];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: false,
		});
		// Should show avatars — use the M1 Avatar class
		const avatars = container.querySelectorAll('.avatar');
		expect(avatars.length).toBe(3);
	});

	it('honors the expanded prop synchronously on first render (no $effect lag)', () => {
		const senders = [makeSender({ id: 'e1', fromName: 'ACME', count: 3 })];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: true,
		});
		// Rows must be present immediately — not after a microtask tick.
		expect(container.querySelector('.sender-row')).not.toBeNull();
		expect(container.querySelector('.bundle-header')?.getAttribute('aria-expanded')).toBe('true');
	});

	it('toggles open/closed when the header is clicked', async () => {
		const senders = [makeSender({ id: 'e1', fromName: 'ACME', count: 3 })];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: false,
		});
		expect(container.querySelector('.sender-row')).toBeNull();
		const header = container.querySelector('.bundle-header') as HTMLElement;
		await fireEvent.click(header);
		expect(container.querySelector('.sender-row')).not.toBeNull();
		await fireEvent.click(header);
		expect(container.querySelector('.sender-row')).toBeNull();
	});

	it('renders overflow count when more than 3 senders', () => {
		const senders = [
			makeSender({ id: 'e1', fromName: 'Alice' }),
			makeSender({ id: 'e2', fromName: 'Bob' }),
			makeSender({ id: 'e3', fromName: 'Carol' }),
			makeSender({ id: 'e4', fromName: 'Dave' }),
		];
		const { container } = render(NewsletterBundle, {
			senders,
			expanded: false,
		});
		// Should show "+1" overflow
		expect(container.textContent).toContain('+1');
	});
});
