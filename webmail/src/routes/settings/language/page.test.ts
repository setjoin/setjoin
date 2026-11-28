import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import LanguagePage from './+page.svelte';

beforeEach(() => {
	localStorage.clear();
	document.documentElement.dataset.theme = 'light';
});

describe('language settings — structural (Task 10)', () => {
	it('renders three locale buttons with aria-pressed attributes', () => {
		const { container } = render(LanguagePage);
		const buttons = container.querySelectorAll('button[aria-pressed]');
		expect(buttons.length).toBeGreaterThanOrEqual(3);
	});

	it('each locale button has aria-pressed matching its selection state', () => {
		const { container } = render(LanguagePage);
		const buttons = container.querySelectorAll('button[aria-pressed]');
		const pressedStates = Array.from(buttons).map((b) =>
			b.getAttribute('aria-pressed')
		);
		// Exactly one button should be active (aria-pressed="true")
		const activeCount = pressedStates.filter((s) => s === 'true').length;
		expect(activeCount).toBe(1);
		// The rest should be false
		const inactiveCount = pressedStates.filter((s) => s === 'false').length;
		expect(inactiveCount).toBe(2);
	});

	it('locale buttons use sj-locale-btn class', () => {
		const { container } = render(LanguagePage);
		const buttons = container.querySelectorAll('button.sj-locale-btn');
		expect(buttons.length).toBe(3);
	});

	it('toggling aria-pressed on click — inactive button becomes active', async () => {
		render(LanguagePage);
		const buttons = screen.getAllByRole('button');
		const inactiveBtn = buttons.find(
			(b) => b.getAttribute('aria-pressed') === 'false'
		) as HTMLButtonElement;
		expect(inactiveBtn).toBeTruthy();
		const initialActive = buttons.find(
			(b) => b.getAttribute('aria-pressed') === 'true'
		);
		expect(initialActive).toBeTruthy();

		await fireEvent.click(inactiveBtn!);
		// The clicked button should now be active
		expect(inactiveBtn!.getAttribute('aria-pressed')).toBe('true');
	});

	it('has no glass-pane class anywhere', () => {
		const { container } = render(LanguagePage);
		expect(container.querySelectorAll('.glass-pane').length).toBe(0);
	});

	it('has no glass-modal class anywhere', () => {
		const { container } = render(LanguagePage);
		expect(container.querySelectorAll('.glass-modal').length).toBe(0);
	});

	it('does not render inline saved text — uses showToast instead', async () => {
		render(LanguagePage);
		// Click a locale button to trigger save
		const buttons = screen.getAllByRole('button');
		const inactiveBtn = buttons.find(
			(b) => b.getAttribute('aria-pressed') === 'false'
		);
		if (inactiveBtn) {
			await fireEvent.click(inactiveBtn);
		}
		// There should be no inline <p> with "Saved" text — showToast handles feedback
		const paragraphs = document.querySelectorAll('p');
		const savedParagraphs = Array.from(paragraphs).filter(
			(p) => p.textContent?.includes('Saved') && !p.closest('[role="status"]')
		);
		expect(savedParagraphs.length).toBe(0);
	});

	it('wraps locale list in a Card component (renders .card class)', () => {
		const { container } = render(LanguagePage);
		const cards = container.querySelectorAll('.card');
		expect(cards.length).toBeGreaterThanOrEqual(1);
	});
});
