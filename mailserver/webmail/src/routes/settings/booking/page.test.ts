import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import BookingSettingsPage from './+page.svelte';

const { listBookingPages, upsertBookingPage, deleteBookingPage, BookingFeatureOffError } = vi.hoisted(() => {
	class BookingFeatureOffError extends Error {}
	return {
		listBookingPages: vi.fn(),
		upsertBookingPage: vi.fn(async () => ({ id: '1' })),
		deleteBookingPage: vi.fn(async () => {}),
		BookingFeatureOffError
	};
});

vi.mock('$lib/api/booking', () => ({
	listBookingPages,
	upsertBookingPage,
	deleteBookingPage,
	BookingFeatureOffError
}));

const SAMPLE_PAGE = {
	id: '1',
	slug: 'jane-30',
	title: '30 min chat',
	description: '',
	durationMinutes: 30,
	bufferMinutes: 0,
	maxPerDay: 8,
	minNoticeMinutes: 120,
	maxAdvanceDays: 60,
	availability: [{ dow: 1, start: '09:00', end: '17:00' }],
	questions: [],
	timezone: 'UTC',
	enabled: true
};

describe('/settings/booking (feature #6 owner settings)', () => {
	beforeEach(() => vi.clearAllMocks());

	it('shows the feature-off notice when the list call 404s (toggle disabled)', async () => {
		listBookingPages.mockRejectedValue(new BookingFeatureOffError('off'));
		render(BookingSettingsPage);
		await waitFor(() => {
			expect(screen.getByText('Booking pages are disabled by your administrator.')).toBeTruthy();
		});
	});

	it('shows an empty state with no pages', async () => {
		listBookingPages.mockResolvedValue([]);
		render(BookingSettingsPage);
		await waitFor(() => {
			expect(screen.getByText('You have no booking pages yet.')).toBeTruthy();
		});
	});

	it('lists an existing page', async () => {
		listBookingPages.mockResolvedValue([SAMPLE_PAGE]);
		render(BookingSettingsPage);
		await waitFor(() => expect(screen.getByText('30 min chat')).toBeTruthy());
		expect(screen.getByText('/book/jane-30')).toBeTruthy();
	});

	it('creating a page submits PUT with the typed slug/title', async () => {
		listBookingPages.mockResolvedValue([]);
		render(BookingSettingsPage);
		await waitFor(() => expect(screen.getByText('You have no booking pages yet.')).toBeTruthy());

		await fireEvent.click(screen.getByText('New booking page'));
		const titleInput = screen.getByLabelText('Page title') as HTMLInputElement;
		const slugInput = screen.getByLabelText('Link name') as HTMLInputElement;
		await fireEvent.input(titleInput, { target: { value: 'Intro call' } });
		await fireEvent.input(slugInput, { target: { value: 'intro-call' } });

		const saveButtons = screen.getAllByText('Save');
		await fireEvent.click(saveButtons[saveButtons.length - 1]);

		await waitFor(() => expect(upsertBookingPage).toHaveBeenCalledTimes(1));
		const call = upsertBookingPage.mock.calls[0] as unknown as [{ slug: string; title: string }];
		const payload = call[0];
		expect(payload.slug).toBe('intro-call');
		expect(payload.title).toBe('Intro call');
	});
});
