import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import HrEvidence from './HrEvidence.svelte';

describe('HrEvidence', () => {
	it('renders leave dates and optional reason only for leave evidence', () => {
		render(HrEvidence, { request: { consumerType: 'hr.leave', payload: { leave_type: 'annual', start_date: '2026-07-01', end_date: '2026-07-03', days: 3, reason: 'Family trip' } } as never });
		expect(screen.getByText(/2026-07-01.*2026-07-03/)).toBeInTheDocument();
		expect(screen.getByText('Family trip')).toBeInTheDocument();
	});

	it('renders expense currency, line items, receipt link, and total', () => {
		render(HrEvidence, { request: { consumerType: 'hr.expense', payload: { currency: 'USD', total_cents: 12345, line_items: [
			{ description: 'Train', category: 'travel', amount_cents: 10000, receipt_sha256: 'abc123', receipt_filename: 'ticket.pdf' },
			{ description: 'Lunch', category: 'meals', amount_cents: 2345 }
		] } } as never });
		expect(screen.getByText('Train')).toBeInTheDocument();
		expect(screen.getByText('Lunch')).toBeInTheDocument();
		const link = screen.getByRole('link');
		expect(link).toHaveAttribute('href', '/api/blobs/abc123');
		expect(link).toHaveAttribute('download', 'ticket.pdf');
		expect(screen.getByText('$123.45')).toBeInTheDocument();
	});

	it('withholds payloads for unrelated consumer types', () => {
		const { container } = render(HrEvidence, { request: { consumerType: 'other', payload: { secret: true } } as never });
		expect(container.textContent).toBe('');
		expect(container.querySelector('*')).toBeNull();
	});
});
