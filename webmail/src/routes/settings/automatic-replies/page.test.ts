import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import AutoRepliesPage from './+page.svelte';

interface AutoReplyWire {
	enabled: boolean;
	subject: string;
	body_internal: string;
	body_internal_html: string;
	body_external: string;
	body_external_html: string;
	start_date: string | null;
	end_date: string | null;
	external_audience: string;
}

// Captured request bodies for PUT assertions.
const putBodies: AutoReplyWire[] = [];

function mockFetch(initial: Partial<AutoReplyWire>) {
	const current: AutoReplyWire = {
		enabled: false,
		subject: '',
		body_internal: '',
		body_internal_html: '',
		body_external: '',
		body_external_html: '',
		start_date: null,
		end_date: null,
		external_audience: 'all',
		...initial,
	};
	return vi.fn((url: string, opts?: RequestInit) => {
		if (!opts || (opts.method ?? 'GET') === 'GET') {
			return Promise.resolve({
				ok: true,
				status: 200,
				json: async () => current,
				text: async () => '',
			} as Response);
		}
		// PUT
		const body = JSON.parse(opts.body as string) as AutoReplyWire;
		putBodies.push(body);
		return Promise.resolve({
			ok: true,
			status: 200,
			json: async () => ({ status: 'saved' }),
			text: async () => '',
		} as Response);
	});
}

describe('Automatic replies settings page (A5)', () => {
	beforeEach(() => {
		putBodies.length = 0;
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.clearAllMocks();
	});

	it('loads existing config and renders the enable switch + subject', async () => {
		vi.stubGlobal(
			'fetch',
			mockFetch({ enabled: true, subject: 'Away', body_internal: 'Back Monday' })
		);
		render(AutoRepliesPage);
		await waitFor(() =>
			expect(screen.getByText('Send automatic replies')).toBeInTheDocument()
		);
		const subject = (await screen.findByLabelText('Subject')) as HTMLInputElement;
		expect(subject.value).toBe('Away');
		const sw = screen.getByRole('switch', { name: /Send automatic replies/i });
		expect((sw as HTMLInputElement).checked).toBe(true);
	});

	it('offers all three external audience values', async () => {
		vi.stubGlobal('fetch', mockFetch({ enabled: true }));
		render(AutoRepliesPage);
		const sel = (await screen.findByLabelText(
			'Reply to people outside my organization'
		)) as HTMLSelectElement;
		const values = Array.from(sel.options).map((o) => o.value).sort();
		expect(values).toEqual(['all', 'contacts', 'none']);
	});

	it('saves the chosen audience and bodies through PUT', async () => {
		vi.stubGlobal('fetch', mockFetch({ enabled: true, external_audience: 'all' }));
		render(AutoRepliesPage);
		const sel = (await screen.findByLabelText(
			'Reply to people outside my organization'
		)) as HTMLSelectElement;
		await fireEvent.change(sel, { target: { value: 'contacts' } });

		const internal = await screen.findByLabelText('Reply to people inside my organization');
		await fireEvent.input(internal, { target: { value: 'Internal note' } });

		await fireEvent.click(screen.getByTestId('ar-save'));
		await waitFor(() => expect(putBodies.length).toBe(1));
		expect(putBodies[0].external_audience).toBe('contacts');
		expect(putBodies[0].body_internal).toBe('Internal note');
		expect(putBodies[0].enabled).toBe(true);
	});

	it('saves each accepted audience value (all/contacts/none)', async () => {
		vi.stubGlobal('fetch', mockFetch({ enabled: true }));
		render(AutoRepliesPage);
		const sel = (await screen.findByLabelText(
			'Reply to people outside my organization'
		)) as HTMLSelectElement;
		for (const v of ['all', 'contacts', 'none']) {
			await fireEvent.change(sel, { target: { value: v } });
			await fireEvent.click(screen.getByTestId('ar-save'));
			await waitFor(() =>
				expect(putBodies[putBodies.length - 1]?.external_audience).toBe(v)
			);
		}
		expect(putBodies.map((b) => b.external_audience)).toEqual(['all', 'contacts', 'none']);
	});

	it('blocks save and shows an error when the date range is inverted', async () => {
		vi.stubGlobal('fetch', mockFetch({ enabled: true }));
		render(AutoRepliesPage);
		// Turn on the scheduled window.
		const schedSwitch = await screen.findByRole('switch', {
			name: /Only send during a time period/i,
		});
		await fireEvent.click(schedSwitch);

		const start = (await screen.findByLabelText('Start date')) as HTMLInputElement;
		const end = (await screen.findByLabelText('End date')) as HTMLInputElement;
		await fireEvent.input(start, { target: { value: '2026-07-10' } });
		await fireEvent.input(end, { target: { value: '2026-07-01' } });

		await fireEvent.click(screen.getByTestId('ar-save'));
		await waitFor(() =>
			expect(
				screen.getByText('The start date must be on or before the end date.')
			).toBeInTheDocument()
		);
		expect(putBodies.length).toBe(0);
	});

	it('sends null dates when the scheduled window is off', async () => {
		vi.stubGlobal(
			'fetch',
			mockFetch({ enabled: true, start_date: '2026-07-01', end_date: '2026-07-09' })
		);
		render(AutoRepliesPage);
		// Wait for load (dates present means the schedule switch is initially on).
		await screen.findByTestId('ar-save');
		const schedSwitch = screen.getByRole('switch', {
			name: /Only send during a time period/i,
		});
		// Turn the window OFF.
		await fireEvent.click(schedSwitch);
		await fireEvent.click(screen.getByTestId('ar-save'));
		await waitFor(() => expect(putBodies.length).toBe(1));
		expect(putBodies[0].start_date).toBeNull();
		expect(putBodies[0].end_date).toBeNull();
	});
});
