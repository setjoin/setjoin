import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const api = vi.hoisted(() => ({ gal: vi.fn(), compose: vi.fn() }));
vi.mock('$lib/jmap/client', () => ({ galSearch: api.gal }));
vi.mock('$lib/stores/compose', () => ({ composeStore: { open: api.compose } }));
import PersonCard from './PersonCard.svelte';

describe('PersonCard', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		api.gal.mockResolvedValue([]);
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('shows an exact directory profile, blob avatar metadata, and its direct manager', async () => {
		api.gal.mockResolvedValue([{ id: 'u/7', displayName: 'Ada Lovelace', email: 'ADA@EXAMPLE.TEST', jobTitle: 'Engineer', department: 'R&D', avatar: { blobId: 'pic/1' } }]);
		vi.mocked(fetch).mockResolvedValue({
			ok: true,
			json: async () => ({ managers: [{ displayName: 'VP' }, { displayName: 'Direct Manager' }] }),
		} as Response);
		render(PersonCard, { email: 'ada@example.test', name: 'Ada' });
		await fireEvent.click(screen.getByRole('button', { name: 'Ada' }));
		expect(await screen.findByRole('dialog', { name: 'Ada Lovelace' })).toBeInTheDocument();
		expect(screen.getByRole('dialog')).toHaveTextContent('Engineer·R&D');
		expect(await screen.findByText('Direct Manager')).toBeInTheDocument();
		expect(screen.getByRole('link', { name: 'View profile' })).toHaveAttribute('href', '/directory');
		expect(fetch).toHaveBeenCalledWith('/auth/me/org-chart?userId=u%2F7', { credentials: 'include' });
	});

	it.each([
		[{ id: '1', displayName: 'Alias', emails: [{ address: 'alias@example.test' }], avatar: 'https://img.test/a.png' }],
		[{ id: '2', displayName: 'Legacy', addresses: [{ email: 'alias@example.test' }] }],
	])('matches alternate directory address shapes', async (card) => {
		api.gal.mockResolvedValue([card]);
		render(PersonCard, { email: 'ALIAS@example.test' });
		await fireEvent.click(screen.getByRole('button', { name: 'ALIAS@example.test' }));
		expect(await screen.findByRole('dialog', { name: card.displayName })).toBeInTheDocument();
	});

	it('degrades to the supplied identity when lookup fails and closes on outside click', async () => {
		api.gal.mockRejectedValue(new Error('directory offline'));
		render(PersonCard, { email: 'external@example.test', name: 'External User' });
		const trigger = screen.getByRole('button', { name: 'External User' });
		await fireEvent.click(trigger);
		expect(await screen.findByText('Not in directory')).toBeInTheDocument();
		expect(screen.queryByRole('link', { name: 'View profile' })).toBeNull();
		await fireEvent.click(document.body);
		await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
	});

	it('opens compose with the exact address and does not repeat lookup on reopen', async () => {
		api.gal.mockResolvedValue([{ id: '1', displayName: 'Ada', email: 'ada@example.test' }]);
		render(PersonCard, { email: 'ada@example.test' });
		const trigger = screen.getByRole('button', { name: 'ada@example.test' });
		await fireEvent.click(trigger);
		await fireEvent.click(await screen.findByRole('button', { name: 'Email' }));
		expect(api.compose).toHaveBeenCalledWith({ to: 'ada@example.test' });
		expect(screen.queryByRole('dialog')).toBeNull();
		await fireEvent.click(trigger);
		expect(await screen.findByRole('dialog')).toBeInTheDocument();
		expect(api.gal).toHaveBeenCalledTimes(1);
	});

	it('closes when the trigger is toggled but ignores clicks inside the popover', async () => {
		render(PersonCard, { email: 'external@example.test' });
		const trigger = screen.getByRole('button', { name: 'external@example.test' });
		await fireEvent.click(trigger);
		const dialog = await screen.findByRole('dialog');
		await fireEvent.click(dialog);
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		await fireEvent.click(trigger);
		expect(screen.queryByRole('dialog')).toBeNull();
	});
});
