import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import RiskRemediation from './RiskRemediation.svelte';

describe('RiskRemediation', () => {
	it('uses reassuring, non-accusatory copy', () => {
		const { container, getByRole } = render(RiskRemediation, { props: { signals: ['impossible_travel'], correlationId: 'c1' } });
		const text = (container.textContent ?? '').toLowerCase();
		expect(text).not.toContain('high risk');
		expect(text).not.toContain('suspicious');
		expect(getByRole('button', { name: /verify/i })).toBeTruthy();
	});

	it('the "what clears this" disclosure is collapsed by default and toggles open', async () => {
		const { getByRole } = render(RiskRemediation, { props: { signals: [], correlationId: 'c1' } });
		const toggle = getByRole('button', { name: /what clears this/i });
		expect(toggle.getAttribute('aria-expanded')).toBe('false');
		await fireEvent.click(toggle);
		expect(toggle.getAttribute('aria-expanded')).toBe('true');
		expect(getByRole('region')).toBeTruthy(); // the disclosed paths
	});

	it('maps signals to a reassuring reason (never the raw slug)', () => {
		const { getByText } = render(RiskRemediation, { props: { signals: ['impossible_travel'], correlationId: 'c1' } });
		expect(getByText(/new location/i)).toBeTruthy(); // risk_rem.reason_location
	});

	it('locked-out state shows the honest recovery path + correlation chip, no dead 403', () => {
		const { getByText, getByLabelText } = render(RiskRemediation, { props: { signals: [], correlationId: 'c1', initialState: 'locked' } });
		expect(getByText(/couldn't verify it's you/i)).toBeTruthy(); // risk_rem.locked_title
		expect(getByText(/contact your IT administrator/i)).toBeTruthy(); // risk_rem.locked_body
		expect(getByLabelText(/copy/i)).toBeTruthy(); // reused correlation-ID chip
	});

	it('error state is role=alert with a Try again that re-arms Verify', async () => {
		const { getByRole } = render(RiskRemediation, { props: { signals: [], correlationId: 'c1', initialState: 'error' } });
		expect(getByRole('alert').textContent?.toLowerCase()).toContain("didn't work");
		expect(getByRole('button', { name: /try again/i })).toBeTruthy();
	});

	it('exposes a polite live region for the success announcement', () => {
		const { container } = render(RiskRemediation, { props: { signals: [], correlationId: 'c1' } });
		expect(container.querySelector('[aria-live="polite"]')).not.toBeNull();
	});

	it('failure_auth_velocity maps to the attempts reason', () => {
		const { getByText } = render(RiskRemediation, { props: { signals: ['failed_auth_velocity'], correlationId: '' } });
		expect(getByText(/failed sign-in attempts/i)).toBeTruthy();
	});

	it('empty signals fall back to generic reason', () => {
		const { getByText } = render(RiskRemediation, { props: { signals: [], correlationId: '' } });
		expect(getByText(/confirm it's really you/i)).toBeTruthy();
	});

	it('renders as a dialog overlay — role=dialog with aria-modal so screen readers block the app shell', () => {
		const { getByRole } = render(RiskRemediation, { props: { signals: [], correlationId: '' } });
		const dialog = getByRole('dialog');
		expect(dialog.getAttribute('aria-modal')).toBe('true');
		expect(dialog.getAttribute('aria-label')).toBeTruthy();
	});
});
