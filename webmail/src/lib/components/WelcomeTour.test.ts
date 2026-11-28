import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { flushSync, tick } from 'svelte';
import WelcomeTour from './WelcomeTour.svelte';
import {
	requestTour,
	consumeRequest,
	hasSeenTour,
	markTourSeen,
	tourUi,
} from '$lib/onboarding/tour.svelte';
import { clearToasts, toasts } from '$lib/components/ui/toasts.svelte';

function nextFrame() {
	return new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
}

async function pump(count = 18) {
	for (let i = 0; i < count; i++) await nextFrame();
	flushSync();
	await tick();
}

function addAnchor(id: string) {
	const element = document.createElement('button');
	element.setAttribute('data-tour', id);
	document.body.appendChild(element);
	return element;
}

function renderTour(
	props: Partial<{
		userEmail: string;
		pathname: string;
		hostBlocked: boolean;
		escapeAllowed: boolean;
		inboxReadiness: 'inactive' | 'loading' | 'loaded-empty' | 'loaded-populated';
	}> = {},
) {
	return render(WelcomeTour, {
		userEmail: 'a@x.test',
		pathname: '/inbox',
		hostBlocked: false,
		escapeAllowed: true,
		inboxReadiness: 'loaded-populated',
		...props,
	});
}

describe('WelcomeTour', () => {
	beforeEach(() => {
		localStorage.clear();
		consumeRequest();
		tourUi.active = false;
		clearToasts();
		document.body.innerHTML = '';
		Element.prototype.getBoundingClientRect = vi.fn(
			() =>
				({
					x: 10,
					y: 10,
					top: 10,
					left: 10,
					right: 110,
					bottom: 50,
					width: 100,
					height: 40,
					toJSON() {},
				}) as DOMRect,
		);
		for (const id of ['apps', 'compose', 'search', 'organize']) addAnchor(id);
	});

	afterEach(() => {
		consumeRequest();
		tourUi.active = false;
		clearToasts();
		vi.restoreAllMocks();
	});

	async function start(force = true) {
		requestTour(force);
		flushSync();
		await pump();
	}

	it('does not render until a tour is requested', () => {
		renderTour();
		expect(screen.queryByRole('region')).toBeNull();
	});

	it('renders four anchored non-modal steps without a blocker, scrim, cutout, or dialog', async () => {
		const { container } = renderTour();
		await start();
		expect(screen.getByRole('region', { name: 'Switch between your apps' })).toBeTruthy();
		expect(screen.getByText('Step 1 of 4')).toBeTruthy();
		expect(container.querySelector('.sj-tour-ring')).toBeTruthy();
		expect(container.querySelector('.sj-tour-blocker')).toBeNull();
		expect(container.querySelector('.sj-tour-cutout')).toBeNull();
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('Next advances and Back returns through the fixed run', async () => {
		renderTour();
		await start();
		await fireEvent.click(screen.getByRole('button', { name: 'Next' }));
		await pump(2);
		expect(screen.getByText('Write a new message')).toBeTruthy();
		expect(screen.getByText('Step 2 of 4')).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Next instead' })).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: 'Back' }));
		await pump(2);
		expect(screen.getByText('Switch between your apps')).toBeTruthy();
	});

	it('loaded-empty freezes a three-step run without Organize', async () => {
		document.querySelector('[data-tour="organize"]')?.remove();
		renderTour({ inboxReadiness: 'loaded-empty' });
		await start();
		expect(screen.getByText('Step 1 of 3')).toBeTruthy();
		expect(screen.queryByText('Organize as you go')).toBeNull();
	});

	it('Skip marks the tour seen and closes', async () => {
		renderTour();
		await start();
		await fireEvent.click(screen.getByRole('button', { name: 'Skip' }));
		expect(screen.queryByRole('region')).toBeNull();
		expect(hasSeenTour('a@x.test')).toBe(true);
	});

	it('Escape skips only when the shell grants dismissal priority', async () => {
		const view = renderTour({ escapeAllowed: false });
		await start();
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(screen.getByRole('region')).toBeTruthy();
		expect(hasSeenTour('a@x.test')).toBe(false);

		await view.rerender({
			userEmail: 'a@x.test',
			pathname: '/inbox',
			hostBlocked: false,
			escapeAllowed: true,
			inboxReadiness: 'loaded-populated',
		});
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(screen.queryByRole('region')).toBeNull();
		expect(hasSeenTour('a@x.test')).toBe(true);
	});

	it('non-forced request is suppressed once seen', async () => {
		markTourSeen('a@x.test');
		renderTour();
		await start(false);
		expect(screen.queryByRole('region')).toBeNull();
	});

	it('preserves and removes the target aria-describedby linkage', async () => {
		const apps = document.querySelector<HTMLElement>('[data-tour="apps"]')!;
		apps.setAttribute('aria-describedby', 'existing-help');
		renderTour();
		await start();
		expect(apps.getAttribute('aria-describedby')).toBe('existing-help sj-tour-body');
		await fireEvent.click(screen.getByRole('button', { name: 'Next' }));
		await pump(2);
		expect(apps.getAttribute('aria-describedby')).toBe('existing-help');
		expect(document.querySelector('[data-tour="compose"]')?.getAttribute('aria-describedby')).toContain('sj-tour-body');
	});

	it('host blocking suspends, clears the card, and resumes at the next step', async () => {
		const view = renderTour();
		await start();
		await view.rerender({
			userEmail: 'a@x.test',
			pathname: '/inbox',
			hostBlocked: true,
			escapeAllowed: false,
			inboxReadiness: 'loaded-populated',
		});
		flushSync();
		expect(screen.queryByRole('region')).toBeNull();

		await view.rerender({
			userEmail: 'a@x.test',
			pathname: '/inbox',
			hostBlocked: false,
			escapeAllowed: true,
			inboxReadiness: 'loaded-populated',
		});
		await pump(2);
		expect(screen.getByText('Write a new message')).toBeTruthy();
	});

	it('outside interaction is ordinary and does not dismiss the tour', async () => {
		renderTour();
		await start();
		await fireEvent.click(document.body);
		expect(screen.getByRole('region')).toBeTruthy();
		expect(hasSeenTour('a@x.test')).toBe(false);
	});

	it('explicit replay focuses the primary action and Done shows the completion toast', async () => {
		renderTour();
		await start();
		await pump(2);
		expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Next' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Next' }));
		await pump(2);
		await fireEvent.click(screen.getByRole('button', { name: 'Next instead' }));
		await pump(2);
		await fireEvent.click(screen.getByRole('button', { name: 'Next' }));
		await pump(2);
		await fireEvent.click(screen.getByRole('button', { name: 'Done' }));
		expect(toasts.at(-1)?.message).toBe(
			'Welcome tour complete. Replay it anytime from Appearance.',
		);
		expect(toasts.at(-1)?.durationMs).toBe(4000);
	});

	it('fail-safe closes and marks seen if active measurement throws', async () => {
		renderTour();
		await start();
		Element.prototype.getBoundingClientRect = vi.fn(() => {
			throw new Error('boom');
		});
		window.dispatchEvent(new Event('resize'));
		await nextFrame();
		await tick();
		expect(screen.queryByRole('region')).toBeNull();
		expect(hasSeenTour('a@x.test')).toBe(true);
	});

	it('route navigation suspends and a return resumes at the next logical step', async () => {
		const view = renderTour();
		await start();
		await view.rerender({
			userEmail: 'a@x.test',
			pathname: '/calendar',
			hostBlocked: false,
			escapeAllowed: true,
			inboxReadiness: 'inactive',
		});
		flushSync();
		expect(screen.queryByRole('region')).toBeNull();
		expect(hasSeenTour('a@x.test')).toBe(false);
		await view.rerender({
			userEmail: 'a@x.test',
			pathname: '/inbox',
			hostBlocked: false,
			escapeAllowed: true,
			inboxReadiness: 'loaded-populated',
		});
		await pump(2);
		expect(screen.getByText('Write a new message')).toBeTruthy();
	});
});
