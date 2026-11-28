// RecordingBanner.test.ts — Meet B2 Task 10: server-state-only, non-
// dismissible, D-5's always-mounted live-region container.
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import RecordingBanner from './RecordingBanner.svelte';

describe('RecordingBanner', () => {
	it('renders the banner text when active', () => {
		render(RecordingBanner, { active: true });
		expect(screen.getByText('This meeting is being recorded')).toBeTruthy();
	});

	it('has no dismiss affordance', () => {
		render(RecordingBanner, { active: true });
		expect(screen.queryByRole('button')).toBeNull();
	});

	it('the live-region container is ALWAYS in the DOM — inactive it persists empty', () => {
		render(RecordingBanner, { active: false });
		const region = screen.getByRole('status');
		expect(region).toBeTruthy();
		expect(region.getAttribute('aria-live')).toBe('polite');
		expect(region.textContent).toBe('');
	});

	it('with stopping true the text switches to the stopping copy', () => {
		render(RecordingBanner, { active: true, stopping: true });
		expect(screen.getByText('Recording is stopping…')).toBeTruthy();
		expect(screen.queryByText('This meeting is being recorded')).toBeNull();
	});

	it('otherwise renders the plain banner copy', () => {
		render(RecordingBanner, { active: true, stopping: false });
		expect(screen.getByText('This meeting is being recorded')).toBeTruthy();
	});
});
