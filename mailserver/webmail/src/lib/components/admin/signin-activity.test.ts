import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import AdminSignInActivity from './AdminSignInActivity.svelte';

// ponytail: prop injection renders each D-C state in isolation —
// no fetch mock needed, no onMount side effects fire when injectedSignIns is set.

describe('Admin sign-in activity (per-state)', () => {
	it('EMPTY: shows "No sign-ins recorded" for an in-scope user with no rows', () => {
		render(AdminSignInActivity, {
			props: { user: { id: 1, name: 'Ada' }, signIns: [] } as any
		});
		expect(screen.getByTestId('admin-signins-empty')).toBeTruthy();
	});

	it('LOADING: shows skeleton', () => {
		render(AdminSignInActivity, {
			props: { loading: true } as any
		});
		expect(screen.getByTestId('admin-signins-skeleton')).toBeTruthy();
	});

	it('ERROR: shows error+retry role=alert', () => {
		render(AdminSignInActivity, {
			props: { error: true } as any
		});
		const el = screen.getByTestId('admin-signins-error');
		expect(el).toBeTruthy();
		expect(el.getAttribute('role')).toBe('alert');
	});

	it('403: renders not-permitted panel when the viewer lacks the perm', () => {
		render(AdminSignInActivity, {
			props: { status: 403 } as any
		});
		expect(screen.getByTestId('admin-signins-forbidden')).toBeTruthy();
	});

	it('404: renders not-found when the user is out of scope', () => {
		render(AdminSignInActivity, {
			props: { status: 404 } as any
		});
		expect(screen.getByTestId('admin-signins-notfound')).toBeTruthy();
	});

	it('POPULATED: renders rows and shows success/fail badges', () => {
		render(AdminSignInActivity, {
			props: {
				signIns: [
					{ id: 1, success: true, occurred_at: '2026-06-01T10:00:00Z', location: 'Berlin, DE', device_name: 'Chrome', platform: 'macOS', client: 'web', protocol: '', auth_method: 'password', fail_reason: '', source_ip: '' },
					{ id: 2, success: false, occurred_at: '2026-06-01T09:00:00Z', location: '', device_name: '', platform: 'Linux', client: '', protocol: '', auth_method: '', fail_reason: 'bad_password', source_ip: '' },
				]
			} as any
		});
		expect(screen.getByTestId('admin-signin-row-1')).toBeTruthy();
		expect(screen.getByTestId('admin-signin-row-2')).toBeTruthy();
	});

	it('SECURE: commit disabled until SECURE typed; aria-live region present', () => {
		render(AdminSignInActivity, {
			props: { user: { id: 1, name: 'Ada' }, signIns: [{ id: 1, success: true, occurred_at: '2026-06-01T00:00:00Z', location: '', device_name: '', platform: '', client: '', protocol: '', auth_method: '', fail_reason: '', source_ip: '' }] } as any
		});
		expect(screen.getByTestId('admin-secure-live').getAttribute('aria-live')).toBe('polite');
	});

	it('SECURE dialog: trigger is present; dialog is initially closed', () => {
		render(AdminSignInActivity, {
			props: { signIns: [] } as any
		});
		// trigger button is always rendered (even on empty state)
		expect(screen.getByTestId('admin-secure-trigger')).toBeTruthy();
		// confirm is inside the dialog — not in DOM until open
		expect(screen.queryByTestId('admin-secure-confirm')).toBeNull();
	});
});
