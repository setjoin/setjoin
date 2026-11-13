// mailserver/webmail/src/lib/components/ui/Tooltip.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { createRawSnippet, tick } from 'svelte';
import Tooltip from './Tooltip.svelte';

const trigger = createRawSnippet(() => ({ render: () => '<button>Archive</button>' }));

function wrapper(container: HTMLElement): HTMLElement {
	return container.querySelector('.tooltip-root') as HTMLElement;
}

describe('Tooltip', () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it('shows after a 500ms hover delay', async () => {
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await fireEvent.mouseEnter(wrapper(container));
		vi.advanceTimersByTime(499);
		await tick();
		expect(screen.queryByRole('tooltip')).toBeNull();
		vi.advanceTimersByTime(1);
		await tick();
		expect(screen.getByRole('tooltip')).toHaveTextContent('Archive conversation');
	});

	it('cancels the pending show when the pointer leaves early', async () => {
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await fireEvent.mouseEnter(wrapper(container));
		vi.advanceTimersByTime(300);
		await fireEvent.mouseLeave(wrapper(container));
		vi.advanceTimersByTime(500);
		await tick();
		expect(screen.queryByRole('tooltip')).toBeNull();
	});

	it('shows immediately on focus', async () => {
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await fireEvent.focusIn(wrapper(container));
		expect(screen.getByRole('tooltip')).toBeInTheDocument();
	});

	it('hides on mouseleave', async () => {
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await fireEvent.mouseEnter(wrapper(container));
		vi.advanceTimersByTime(500);
		await tick();
		expect(screen.getByRole('tooltip')).toBeInTheDocument();
		await fireEvent.mouseLeave(wrapper(container));
		expect(screen.queryByRole('tooltip')).toBeNull();
	});

	it('hides on blur', async () => {
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await fireEvent.focusIn(wrapper(container));
		expect(screen.getByRole('tooltip')).toBeInTheDocument();
		await fireEvent.focusOut(wrapper(container));
		expect(screen.queryByRole('tooltip')).toBeNull();
	});

	it('hides on Escape', async () => {
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await fireEvent.focusIn(wrapper(container));
		expect(screen.getByRole('tooltip')).toBeInTheDocument();
		await fireEvent.keyDown(window, { key: 'Escape' });
		expect(screen.queryByRole('tooltip')).toBeNull();
	});

	it('links the trigger to the tooltip via aria-describedby', async () => {
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await tick();
		const btn = screen.getByRole('button', { name: 'Archive' });
		const describedBy = btn.getAttribute('aria-describedby');
		expect(describedBy).toBeTruthy();
		await fireEvent.focusIn(wrapper(container));
		expect(screen.getByRole('tooltip').id).toBe(describedBy);
	});

	it('flips below the trigger when there is no room above', async () => {
		// jsdom reports zero-size rects, so "no room above" is the deterministic branch here.
		const { container } = render(Tooltip, { text: 'Archive conversation', children: trigger });
		await fireEvent.focusIn(wrapper(container));
		await tick();
		expect(screen.getByRole('tooltip').dataset.placement).toBe('below');
	});
});
