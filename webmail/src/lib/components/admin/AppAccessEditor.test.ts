import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import { jmapSession } from '$lib/stores/session';
import AppAccessEditor from './AppAccessEditor.svelte';

const adminUserAppAccess = vi.fn();
const adminUserSetAppAccess = vi.fn();
const adminFeatureList = vi.fn();

vi.mock('$lib/admin/client', async () => {
	const actual = await vi.importActual<typeof import('$lib/admin/client')>('$lib/admin/client');
	return {
		...actual,
		adminUserAppAccess: (...args: unknown[]) => adminUserAppAccess(...args),
		adminUserSetAppAccess: (...args: unknown[]) => adminUserSetAppAccess(...args),
		adminFeatureList: (...args: unknown[]) => adminFeatureList(...args),
	};
});

describe('AppAccessEditor', () => {
	beforeEach(() => {
		jmapSession.set({ capabilities: { 'urn:setjoin:params:jmap:mail': {
			admin: { consoles: ['auth'], permissions: ['users.create'] },
		} } } as any);
		adminUserAppAccess.mockReset().mockResolvedValue([
			{ app: 'mail', enabled: true }, { app: 'calendar', enabled: true },
			{ app: 'contacts', enabled: true }, { app: 'tasks', enabled: true },
			{ app: 'chat', enabled: true }, { app: 'drive', enabled: false },
			{ app: 'meet', enabled: true },
		]);
		adminUserSetAppAccess.mockReset().mockResolvedValue(undefined);
		adminFeatureList.mockReset().mockResolvedValue([]);
	});

	afterEach(() => vi.restoreAllMocks());

	it('shows seven editable app switches for members', async () => {
		render(AppAccessEditor, { open: true, userId: 8, userEmail: 'member@example.com' });
		await waitFor(() => expect(screen.getByRole('switch', { name: 'Chat' })).toBeInTheDocument());
		expect(screen.getAllByRole('switch')).toHaveLength(7);
		await fireEvent.click(screen.getByRole('switch', { name: 'Drive' }));
		expect(adminUserSetAppAccess).toHaveBeenCalledWith(8, 'drive', true);
	});

	it('shows seven profile-derived read-only rows for guests and never PUTs app access', async () => {
		render(AppAccessEditor, {
			open: true,
			userId: 9,
			userEmail: 'guest@example.net',
			guestEntitlements: {
				mail: false, calendar: false, contacts: false, tasks: false,
				chat: true, drive: true, meet: false,
			},
			guestProfileName: 'Partner',
		});
		await waitFor(() => expect(screen.getByText('Profile-derived from Partner')).toBeInTheDocument());
		const switches = screen.getAllByRole('switch');
		expect(switches).toHaveLength(7);
		expect(switches.every((control) => control.hasAttribute('disabled'))).toBe(true);
		await fireEvent.click(switches[4]);
		expect(adminUserSetAppAccess).not.toHaveBeenCalled();
		expect(adminUserAppAccess).not.toHaveBeenCalled();
	});
});
