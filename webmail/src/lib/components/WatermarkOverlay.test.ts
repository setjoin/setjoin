import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import WatermarkOverlay from './WatermarkOverlay.svelte';

describe('WatermarkOverlay', () => {
	it('renders the user email when enabled', () => {
		const { getAllByText } = render(WatermarkOverlay, {
			props: { enabled: true, userEmail: 'a@b.com' }
		});
		// Tiled: the stamp repeats, so there is MORE THAN ONE occurrence.
		expect(getAllByText(/a@b\.com/).length).toBeGreaterThan(1);
	});

	it('is aria-hidden and non-interactive (decorator, not content)', () => {
		const { container } = render(WatermarkOverlay, {
			props: { enabled: true, userEmail: 'a@b.com' }
		});
		const layer = container.querySelector('.watermark') as HTMLElement;
		expect(layer.getAttribute('aria-hidden')).toBe('true');
		expect(getComputedStyle(layer).pointerEvents).toBe('none');
	});

	it('renders nothing when disabled', () => {
		const { queryByText } = render(WatermarkOverlay, {
			props: { enabled: false, userEmail: 'a@b.com' }
		});
		expect(queryByText(/a@b\.com/)).toBeNull();
	});
});
