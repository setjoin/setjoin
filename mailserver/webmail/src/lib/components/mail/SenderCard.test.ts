import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import SenderCard from './SenderCard.svelte';

// Mock the JMAP client + contacts store the card looks the sender up through,
// plus the VIP-senders store (own network calls, covered by vipSenders' own tests).
const mocks = vi.hoisted(() => ({
	contactQuery: vi.fn(),
	contactGet: vi.fn(),
	galSearch: vi.fn(),
	createContact: vi.fn(),
	vipLoad: vi.fn(),
	vipSet: vi.fn(),
	vipIsVip: vi.fn(),
}));

vi.mock('$lib/jmap/client', () => ({
	contactQuery: mocks.contactQuery,
	contactGet: mocks.contactGet,
	galSearch: mocks.galSearch,
}));
vi.mock('$lib/stores/contacts', () => ({
	createContact: mocks.createContact,
}));
vi.mock('$lib/stores/vipSenders.svelte', () => ({
	vipSenders: {
		loaded: true,
		load: mocks.vipLoad,
		set: mocks.vipSet,
		isVip: mocks.vipIsVip,
	},
}));

beforeEach(() => {
	vi.clearAllMocks();
	mocks.contactQuery.mockResolvedValue({ ids: [] });
	mocks.contactGet.mockResolvedValue([]);
	mocks.galSearch.mockResolvedValue([]);
	mocks.createContact.mockResolvedValue('new-id');
	mocks.vipLoad.mockResolvedValue(undefined);
	mocks.vipSet.mockResolvedValue(undefined);
	mocks.vipIsVip.mockReturnValue(false);
});

describe('SenderCard', () => {
	it('renders the looked-up personal contact and hides the add button', async () => {
		mocks.contactQuery.mockResolvedValue({ ids: ['c1'] });
		mocks.contactGet.mockResolvedValue([
			{ id: 'c1', displayName: 'Bob Boss', company: 'ACME', jobTitle: 'CTO', emails: [{ type: 'work', address: 'bob@acme.com' }] },
		]);

		const { container, getByLabelText } = render(SenderCard, { name: 'Bob', email: 'bob@acme.com' });
		await fireEvent.click(getByLabelText('Sender details'));

		await vi.waitFor(() => expect(container.textContent).toContain('Bob Boss'));
		expect(container.textContent).toContain('ACME');
		expect(container.textContent).toContain('CTO');
		expect(mocks.galSearch).not.toHaveBeenCalled(); // exact personal match → no GAL fallback
		expect(container.textContent).not.toContain('Add to contacts');
	});

	it('exact-matches the lowercased email (substring query must not false-dedup)', async () => {
		// contactQuery is a substring ILIKE — a non-exact hit must be rejected, so the
		// card falls through to GAL.
		mocks.contactQuery.mockResolvedValue({ ids: ['c9'] });
		mocks.contactGet.mockResolvedValue([
			{ id: 'c9', displayName: 'Bobby Other', emails: [{ type: 'work', address: 'bobby@acme.com' }] },
		]);
		mocks.galSearch.mockResolvedValue([{ id: 'g1', displayName: 'GAL Bob', email: 'bob@acme.com' }]);

		const { container, getByLabelText } = render(SenderCard, { name: 'Bob', email: 'bob@acme.com' });
		await fireEvent.click(getByLabelText('Sender details'));

		await vi.waitFor(() => expect(container.textContent).toContain('GAL Bob'));
		expect(mocks.galSearch).toHaveBeenCalledWith('bob@acme.com');
		// GAL hit is not a personal contact → the add button is offered.
		expect(container.textContent).toContain('Add to contacts');
	});

	it('add-to-contacts calls createContact with the sender email (address, not value)', async () => {
		const { getByLabelText, getByText } = render(SenderCard, { name: 'New Person', email: 'new@x.com' });
		await fireEvent.click(getByLabelText('Sender details'));

		await vi.waitFor(() => expect(getByText('Add to contacts')).toBeTruthy());
		await fireEvent.click(getByText('Add to contacts'));

		expect(mocks.createContact).toHaveBeenCalledWith({
			displayName: 'New Person',
			emails: [{ type: 'other', address: 'new@x.com' }],
		});
	});

	it('toggles VIP membership via the star button', async () => {
		const { getByLabelText } = render(SenderCard, { name: 'Bob', email: 'Bob@Acme.com' });
		await fireEvent.click(getByLabelText('Sender details'));

		await fireEvent.click(getByLabelText('Mark as VIP'));
		expect(mocks.vipSet).toHaveBeenCalledWith('Bob@Acme.com', true);
	});
});
