import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import * as client from '$lib/admin/client';
import Page from './+page.svelte';

interface LogEntry {
	id: number;
	userId?: number | null;
	email: string;
	event: string;
	provider: string;
	ipAddress: string;
	occurredAt: string;
}

function res(body: unknown) {
	return { ok: true, status: 200, json: async () => body } as Response;
}

const entries: LogEntry[] = [
	{
		id: 1,
		userId: 11,
		email: 'alice@test.local',
		event: 'login_success',
		provider: 'password',
		ipAddress: '10.0.0.1',
		occurredAt: '2026-01-02T03:04:05Z'
	},
	{
		id: 2,
		userId: null,
		email: 'bob@test.local',
		event: 'mfa_failure',
		provider: 'totp',
		ipAddress: '10.0.0.2',
		occurredAt: '2026-02-03T04:05:06Z'
	},
	{
		id: 3,
		userId: null,
		email: 'carol@test.local',
		event: 'vendor_unknown_event',
		provider: 'sso',
		ipAddress: '10.0.0.3',
		occurredAt: '2026-03-04T05:06:07Z'
	}
];

function lastCalledUrl(): string {
	const calls = vi.mocked(client.adminFetch).mock.calls;
	return calls[calls.length - 1][0] as string;
}

describe('/admin/auth-log', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.spyOn(client, 'adminFetch').mockResolvedValue(res(entries));
	});
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('loads entries and renders mapped table rows', async () => {
		render(Page);

		expect(await screen.findByText('alice@test.local')).toBeInTheDocument();
		expect(screen.getByText('bob@test.local')).toBeInTheDocument();
		// eventLabel maps known events and falls through unknown ones verbatim.
		expect(screen.getByText('Login success')).toBeInTheDocument();
		expect(screen.getByText('MFA failure')).toBeInTheDocument();
		expect(screen.getByText('vendor_unknown_event')).toBeInTheDocument();
		expect(screen.getByText('totp')).toBeInTheDocument();
		expect(screen.getByText('10.0.0.3')).toBeInTheDocument();
		// formatTime renders a localized timestamp containing the year.
		expect(screen.getAllByText(/2026/).length).toBe(3);
		// No filters set → only the limit param, in column order.
		expect(client.adminFetch).toHaveBeenCalledTimes(1);
		expect(lastCalledUrl()).toBe('/admin/auth-log?limit=200');
	});

	it('applies email, event and provider filters when searching', async () => {
		vi.mocked(client.adminFetch).mockResolvedValueOnce(res(entries));
		render(Page);
		await screen.findByText('alice@test.local');

		vi.mocked(client.adminFetch).mockResolvedValueOnce(
			res([entries[1]])
		);
		await fireEvent.input(screen.getByPlaceholderText('Filter by email'), {
			target: { value: 'bob@test.local' }
		});
		await fireEvent.input(screen.getByPlaceholderText('Filter by event'), {
			target: { value: 'mfa_failure' }
		});
		await fireEvent.input(screen.getByPlaceholderText('Filter by provider'), {
			target: { value: 'totp' }
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));

		await waitFor(() => expect(client.adminFetch).toHaveBeenCalledTimes(2));
		const params = new URLSearchParams(lastCalledUrl().split('?')[1]);
		expect(params.get('email')).toBe('bob@test.local');
		expect(params.get('event')).toBe('mfa_failure');
		expect(params.get('provider')).toBe('totp');
		expect(params.get('limit')).toBe('200');
		expect(await screen.findByText('bob@test.local')).toBeInTheDocument();
		expect(screen.queryByText('alice@test.local')).not.toBeInTheDocument();
	});

	it('shows the error state and recovers via Retry', async () => {
		vi.mocked(client.adminFetch).mockRejectedValueOnce(new Error('auth log offline'));
		render(Page);

		expect(await screen.findByText('auth log offline')).toBeInTheDocument();
		expect(screen.queryByText('alice@test.local')).not.toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		expect(await screen.findByText('alice@test.local')).toBeInTheDocument();
		expect(client.adminFetch).toHaveBeenCalledTimes(2);
	});

	it('renders the empty state when no entries exist', async () => {
		vi.mocked(client.adminFetch).mockResolvedValue(res([]));
		render(Page);

		expect(await screen.findByText('No auth log entries found.')).toBeInTheDocument();
		expect(screen.queryByRole('table')).not.toBeInTheDocument();
	});

	it('shows the loading state while the request is in flight', async () => {
		let resolveList!: (value: LogEntry[]) => void;
		vi.mocked(client.adminFetch).mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					resolveList = (value: LogEntry[]) => resolve(res(value));
				})
		);
		const { container } = render(Page);

		expect(container.querySelector('.auth-log-empty')).toBeTruthy();
		expect(screen.getByRole('status')).toBeInTheDocument();
		expect(screen.getByText('Loading health data…')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Search' })).toBeDisabled();

		resolveList(entries);
		expect(await screen.findByText('alice@test.local')).toBeInTheDocument();
	});
});
