import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render } from '@testing-library/svelte/svelte5';
import SearchIntentRail from './SearchIntentRail.svelte';

const intent = {
	version: 1 as const,
	source: 'typed' as const,
	confidence: 'exact' as const,
	filters: [{ kind: 'keyword' as const, value: 'unread' as const }],
};

describe('SearchIntentRail', () => {
	it('keeps zero-result broadening explicit and user-controlled', async () => {
		const onEdit = vi.fn();
		const { getByRole, getByLabelText } = render(SearchIntentRail, {
			intent, mailboxes: [], onEdit, onApply: vi.fn(), zeroResults: true,
		});
		expect(getByRole('status').textContent).toContain('will not broaden it automatically');
		await fireEvent.click(getByLabelText(/Remove filter/));
		expect(onEdit).toHaveBeenCalledWith('');
	});
});
