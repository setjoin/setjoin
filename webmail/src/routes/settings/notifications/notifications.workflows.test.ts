import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const push = vi.hoisted(() => ({ permissionState: vi.fn(), enable: vi.fn() }));
vi.mock('$lib/push/subscribe', () => ({
	permissionState: push.permissionState,
	enablePushNotifications: push.enable,
}));

import Page from './+page.svelte';

const initial = {
	push_enabled: true,
	push_sound: 'chime',
	stop_push_when_desktop_online: false,
	dnd_start: '22:00',
	dnd_end: '07:00',
	dnd_days: 1,
	mail_notifications: 'important',
	calendar_reminders: true,
	task_reminders: false,
};

function response(data: unknown, ok = true): Response {
	return { ok, json: async () => data } as Response;
}

describe('notification settings workflows', () => {
	beforeEach(() => {
		push.permissionState.mockReset().mockReturnValue('not-asked');
		push.enable.mockReset();
	});
	afterEach(() => vi.unstubAllGlobals());

	it('loads the global preference, edits every field, toggles day bits, and saves bounded JSON', async () => {
		const fetchMock = vi.fn()
			.mockResolvedValueOnce(response({ preferences: [{ ...initial, device_fingerprint: 'device' }, initial] }))
			.mockResolvedValueOnce(response({}));
		vi.stubGlobal('fetch', fetchMock);
		render(Page);
		await waitFor(() => expect(screen.getByLabelText('Notification sound')).toHaveValue('chime'));
		await fireEvent.click(screen.getByText('Tue'));
		await fireEvent.click(screen.getByText('Mon'));
		await fireEvent.change(screen.getByLabelText('Notification sound'), { target: { value: 'silent' } });
		await fireEvent.change(screen.getByLabelText('Notify me about'), { target: { value: 'off' } });
		await fireEvent.input(screen.getByLabelText('Start time'), { target: { value: '' } });
		await fireEvent.input(screen.getByLabelText('End time'), { target: { value: '06:30' } });
		await fireEvent.click(screen.getByText('Enable push notifications'));
		await fireEvent.click(screen.getByText('Calendar event reminders'));
		await fireEvent.click(screen.getByText('Task due date reminders'));
		await fireEvent.click(screen.getByText('Save'));
		await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
		const request = fetchMock.mock.calls[1][1] as RequestInit;
		expect(request.method).toBe('PUT');
		expect(JSON.parse(String(request.body))).toEqual({ preferences: {
			push_enabled: false,
			push_sound: 'silent',
			stop_push_when_desktop_online: false,
			dnd_start: null,
			dnd_end: '06:30',
			dnd_days: 2,
			mail_notifications: 'off',
			calendar_reminders: false,
			task_reminders: true,
		} });
	});

	it('restores the last persisted values on cancel', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ preferences: [initial] })));
		render(Page);
		await waitFor(() => expect(screen.getByLabelText('Notification sound')).toHaveValue('chime'));
		await fireEvent.change(screen.getByLabelText('Notification sound'), { target: { value: 'ping' } });
		await fireEvent.click(screen.getByText('Sun'));
		await fireEvent.click(screen.getByText('Cancel'));
		expect(screen.getByLabelText('Notification sound')).toHaveValue('chime');
		expect(screen.getByText('Sun')).not.toHaveClass('sj-chip-active');
	});

	it('surfaces load, HTTP-save, malformed-save, and network-save failures', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
		const first = render(Page);
		await waitFor(() => expect(screen.getByText('offline')).toBeInTheDocument());
		first.unmount();

		const fetchMock = vi.fn()
			.mockResolvedValueOnce(response({ preferences: [initial] }))
			.mockResolvedValueOnce(response({ error: 'policy denied' }, false));
		vi.stubGlobal('fetch', fetchMock);
		const second = render(Page);
		await waitFor(() => expect(screen.getByText('Save')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Save'));
		await waitFor(() => expect(screen.getByText('policy denied')).toBeInTheDocument());
		second.unmount();

		const badJson = { ok: false, json: vi.fn().mockRejectedValue(new Error('bad json')) } as unknown as Response;
		vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response({ preferences: [] })).mockResolvedValueOnce(badJson));
		render(Page);
		await waitFor(() => expect(screen.getByText('Save')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Save'));
		await waitFor(() => expect(screen.getByText('Unknown error')).toBeInTheDocument());
	});

	it('enables browser push only from the explicit button and handles denial and failure', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ preferences: [] })));
		push.enable.mockResolvedValueOnce('granted');
		const first = render(Page);
		await waitFor(() => expect(screen.getByText('Enable mail notifications')).toBeInTheDocument());
		expect(push.enable).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByText('Enable mail notifications'));
		await waitFor(() => expect(screen.getByText('Notifications are enabled on this device.')).toBeInTheDocument());
		first.unmount();

		push.enable.mockResolvedValueOnce('denied');
		const second = render(Page);
		await waitFor(() => expect(screen.getByText('Enable mail notifications')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Enable mail notifications'));
		await waitFor(() => expect(screen.getByText(/Notifications are blocked/)).toBeInTheDocument());
		second.unmount();

		push.enable.mockRejectedValueOnce(new Error('subscribe failed'));
		render(Page);
		await waitFor(() => expect(screen.getByText('Enable mail notifications')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Enable mail notifications'));
		await waitFor(() => expect(screen.getByText(/Couldn.t enable notifications/i)).toBeInTheDocument());
	});
});
