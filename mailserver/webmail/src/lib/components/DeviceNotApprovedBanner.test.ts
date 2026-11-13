import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import DeviceNotApprovedBanner from './DeviceNotApprovedBanner.svelte';

describe('DeviceNotApprovedBanner', () => {
	it('renders the honest message when not approved (report-only session)', () => {
		const { getByRole } = render(DeviceNotApprovedBanner, { props: { lockedDown: true, approved: false } });
		expect(getByRole('alert')).toBeTruthy();
	});
	it('renders nothing when approved', () => {
		const { container } = render(DeviceNotApprovedBanner, { props: { lockedDown: true, approved: true } });
		expect(container.textContent?.trim()).toBe('');
	});
	it('renders nothing when lockdown is off (report-only is the only soft-banner trigger)', () => {
		const { container } = render(DeviceNotApprovedBanner, { props: { lockedDown: false, approved: false } });
		expect(container.textContent?.trim()).toBe('');
	});
});
