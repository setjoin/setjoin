import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import CertStatusCard from './CertStatusCard.svelte';

describe('CertStatusCard', () => {
	it('shows an active badge for a valid cert', () => {
		const { getByText } = render(CertStatusCard, { props: { status: { status: 'valid', subject_cn: 'alice@corp', expires_at: '2027-01-01T00:00:00Z' } } });
		expect(getByText(/active/i)).toBeTruthy();
		expect(getByText(/alice@corp/i)).toBeTruthy();
	});

	it('shows a warm empty state when no cert is presented', () => {
		const { getByText } = render(CertStatusCard, { props: { status: { status: 'none' } } });
		expect(getByText(/no security certificate/i)).toBeTruthy();
	});

	it('flags an expired cert with renew guidance, not blame', () => {
		const { getAllByText, container } = render(CertStatusCard, { props: { status: { status: 'expired' } } });
		expect(getAllByText(/expired/i).length).toBeGreaterThan(0);
		expect((container.textContent ?? '').toLowerCase()).not.toContain('you did');
	});

	it('shows an expiring-soon warning badge with a day count', () => {
		const { getByText } = render(CertStatusCard, { props: { status: { status: 'expiring', expires_in_days: 12, subject_cn: 'alice@corp' } } });
		expect(getByText(/12 days/i)).toBeTruthy(); // cert.expiring with {n}
		expect(getByText(/renew/i)).toBeTruthy();   // cert.expiring_hint
	});

	it('renders a loading spinner while fetching', () => {
		const { getByRole } = render(CertStatusCard, { props: { loading: true } });
		expect(getByRole('status')).toBeTruthy(); // Spinner exposes role=status
	});

	it('shows an error strip with role=alert + Retry on a fetch failure', () => {
		const { getByRole } = render(CertStatusCard, { props: { error: true } });
		expect(getByRole('alert').textContent?.toLowerCase()).toContain('load');
		expect(getByRole('button', { name: /retry/i })).toBeTruthy();
	});

	it('announces the resolved status via a polite live region', () => {
		const { container } = render(CertStatusCard, { props: { status: { status: 'valid', subject_cn: 'a@c', expires_at: '2027-01-01T00:00:00Z' } } });
		expect(container.querySelector('[aria-live="polite"]')).not.toBeNull();
	});
});
