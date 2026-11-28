import { describe, it, expect, beforeEach } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';
import { get } from 'svelte/store';
import { tick } from 'svelte';
import { composeStore } from '$lib/stores/compose';
import ComposeDock from './ComposeDock.svelte';

describe('ComposeDock — minimized-compose dock (QoL #18)', () => {
	beforeEach(() => composeStore.reset());

	it('renders nothing when no session is minimized', () => {
		composeStore.open(); // maximized, not minimized
		render(ComposeDock);
		expect(screen.queryByTestId('compose-dock')).toBeNull();
	});

	it('renders one bar per minimized session showing subject (recipient fallback)', async () => {
		const a = composeStore.open()!;
		const b = composeStore.open()!; // opening b minimized a
		composeStore.setMeta(a, { subject: 'Quarterly report' });
		composeStore.setMeta(b, { recipient: 'bob@x.test' });
		composeStore.minimize(b); // both minimized now
		render(ComposeDock);
		await tick();
		expect(screen.getByTestId('compose-dock')).toBeInTheDocument();
		expect(screen.getByText('Quarterly report')).toBeInTheDocument();
		expect(screen.getByText('bob@x.test')).toBeInTheDocument();
	});

	it('shows an autosave-error badge on a minimized draft that failed to save', async () => {
		const a = composeStore.open()!;
		composeStore.open(); // minimizes a
		composeStore.setMeta(a, { subject: 'Broken draft', saveError: true });
		render(ComposeDock);
		await tick();
		expect(screen.getByLabelText("Draft couldn't be saved")).toBeInTheDocument();
	});

	it('clicking a bar restores it (maximizes; the swap minimizes any current maximized)', async () => {
		const a = composeStore.open()!;
		composeStore.setMeta(a, { subject: 'Restore me' });
		composeStore.open(); // minimizes a, opens a second maximized
		composeStore.minimize(a); // ensure a is in the dock
		render(ComposeDock);
		await tick();
		await fireEvent.click(screen.getByText('Restore me'));
		expect(get(composeStore).sessions.find((s) => s.id === a)!.minimized).toBe(false);
	});

	it('bar close button removes that session', async () => {
		const a = composeStore.open()!;
		composeStore.open(); // minimizes a
		render(ComposeDock);
		await tick();
		await fireEvent.click(screen.getByLabelText('Close'));
		expect(get(composeStore).sessions.some((s) => s.id === a)).toBe(false);
	});

	it('uses roving tabindex — exactly one bar button is in the tab order', async () => {
		composeStore.open();
		composeStore.open();
		composeStore.open(); // three sessions; two minimized
		render(ComposeDock);
		await tick();
		const bars = screen.getAllByTestId('compose-pill');
		expect(bars.length).toBeGreaterThanOrEqual(2);
		const inTabOrder = bars.filter((b) => b.getAttribute('tabindex') === '0');
		expect(inTabOrder).toHaveLength(1);
	});
});
