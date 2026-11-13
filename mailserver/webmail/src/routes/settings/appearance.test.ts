import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import { goto } from '$app/navigation';
import Page from './appearance/+page.svelte';
import * as tour from '$lib/onboarding/tour.svelte';

describe('appearance settings — replay tour', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		tour.consumeRequest();
	});

	it('replays the tour: navigates to /inbox then requests the tour', async () => {
		render(Page);
		await fireEvent.click(screen.getByText('Replay welcome tour'));
		await tick(); // let the async handler's `await goto(...)` resolve
		expect(goto).toHaveBeenCalledWith('/inbox');
		expect(tour.tourRequest.pending).toBe(true);
		expect(tour.tourRequest.force).toBe(true);
	});
});
