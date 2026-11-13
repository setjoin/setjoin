import { describe, it, expect, vi } from 'vitest';
import { tick } from 'svelte';

// Simulate keyboard events on document.body
function press(key: string, ctrlKey = false, metaKey = false) {
	document.body.dispatchEvent(
		new KeyboardEvent('keydown', { key, ctrlKey, metaKey, bubbles: true })
	);
}

describe('useKeyboard', () => {
	it('registers a single-key shortcut and fires callback', async () => {
		const fn = vi.fn();
		const cleanup = (await import('./useKeyboard.svelte')).registerShortcut('r', fn);
		press('r');
		await tick();
		expect(fn).toHaveBeenCalledTimes(1);
		cleanup();
	});

	it('does not fire when input field is focused', async () => {
		const fn = vi.fn();
		const input = document.createElement('input');
		document.body.appendChild(input);
		input.focus();
		const cleanup = (await import('./useKeyboard.svelte')).registerShortcut('r', fn);
		press('r');
		await tick();
		expect(fn).not.toHaveBeenCalled();
		document.body.removeChild(input);
		cleanup();
	});

	it('fires Ctrl+K for command palette', async () => {
		const fn = vi.fn();
		const cleanup = (await import('./useKeyboard.svelte')).registerShortcut('k', fn, { ctrl: true });
		press('k', true, false);
		await tick();
		expect(fn).toHaveBeenCalledTimes(1);
		cleanup();
	});
});
