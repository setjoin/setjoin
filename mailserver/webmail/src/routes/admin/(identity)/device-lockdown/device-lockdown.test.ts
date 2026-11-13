import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import DeviceLockdownPage from './+page.svelte';

const client = vi.hoisted(() => ({ adminFetch: vi.fn() }));
vi.mock('$lib/admin/client', () => client);

const rows = [
	{
		id: 11,
		user_email: 'alice@example.test',
		user_display_name: 'Alice',
		enroll_state: 'enrolled',
		platform: 'macOS',
		requested_at: '2026-07-22T00:00:00Z',
		device_name: 'Alice Mac',
	},
	{
		id: 12,
		user_email: 'bob@example.test',
		enroll_state: 'approved',
		platform: 'Linux',
		last_seen_at: '2026-07-22T01:00:00Z',
		device_name: 'Bob Laptop',
	},
];

function response(data: unknown, status = 200) {
	return { ok: status < 400, status, json: async () => data, text: async () => '' };
}

describe('device lockdown admin page', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: true })));
		client.adminFetch.mockImplementation(async (path: string) => {
			if (path.startsWith('/admin/devices/queue?')) return response(rows);
			if (path.startsWith('/admin/devices?user_id=')) return response([rows[1]]);
			return response({});
		});
	});

	it('renders queue detail, approves a waiting device, and announces the result', async () => {
		render(DeviceLockdownPage);
		expect(await screen.findByText('Alice')).toBeInTheDocument();
		expect(screen.getByText('2 devices waiting')).toBeInTheDocument();
		expect(document.querySelector('.page-wrap')).toHaveAttribute('data-reduced-motion', 'true');

		await fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
		await waitFor(() => expect(client.adminFetch).toHaveBeenCalledWith('/admin/devices/11/approve', { method: 'POST' }));
		expect(screen.getByText("Approved Alice's device.")).toBeInTheDocument();
		expect(screen.queryByText('Alice')).toBeNull();
	});

	it('requires reason and type-to-confirm, then keeps a failed revoke inline', async () => {
		client.adminFetch.mockImplementation(async (path: string) => {
			if (path.startsWith('/admin/devices/queue?')) return response(rows);
			if (path === '/admin/devices/12/revoke') throw new Error('Device state changed; refresh required');
			return response({});
		});
		render(DeviceLockdownPage);
		await fireEvent.click(await screen.findByRole('button', { name: 'Revoke Bob Laptop' }));
		const commit = screen.getByRole('button', { name: 'Revoke & wipe' });
		expect(commit).toBeDisabled();
		await fireEvent.input(screen.getByLabelText('Reason (required)'), { target: { value: 'Lost device' } });
		await fireEvent.input(screen.getByLabelText(/type revoke/i), { target: { value: 'REVOKE' } });
		expect(commit).not.toBeDisabled();
		await fireEvent.click(commit);
		expect(await screen.findByRole('alert')).toHaveTextContent('Device state changed; refresh required');
		expect(screen.getByRole('dialog')).toBeInTheDocument();
	});

	it('drills into a user, encodes the lookup, and shows their device', async () => {
		render(DeviceLockdownPage);
		await fireEvent.click(await screen.findByRole('button', { name: "View Alice's devices" }));
		await waitFor(() => expect(client.adminFetch).toHaveBeenCalledWith('/admin/devices?user_id=alice%40example.test'));
		expect(screen.getByRole('tab', { name: 'By user' })).toHaveAttribute('aria-selected', 'true');
		expect(screen.getByText('Bob Laptop')).toBeInTheDocument();
	});

	it('shows caught-up and failure states with working recovery actions', async () => {
		client.adminFetch.mockResolvedValueOnce(response([]));
		render(DeviceLockdownPage);
		expect(await screen.findByText(/all caught up/i)).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Show all devices' }));
		await waitFor(() => expect(client.adminFetch).toHaveBeenCalledTimes(2));
	});
});
