import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent } from '@testing-library/svelte/svelte5';
import { focusTrap } from './focusTrap';

function makeContainer(numButtons = 2): { container: HTMLDivElement; buttons: HTMLButtonElement[] } {
	const container = document.createElement('div');
	container.setAttribute('tabindex', '-1');
	const buttons: HTMLButtonElement[] = [];
	for (let i = 0; i < numButtons; i++) {
		const btn = document.createElement('button');
		btn.textContent = `Button ${i + 1}`;
		container.appendChild(btn);
		buttons.push(btn);
	}
	document.body.appendChild(container);
	return { container, buttons };
}

describe('focusTrap action', () => {
	beforeEach(() => {
		document.body.innerHTML = '';
	});

	it('focuses the node on mount', () => {
		const { container } = makeContainer();
		const action = focusTrap(container);
		expect(document.activeElement).toBe(container);
		action.destroy();
	});

	it('restores focus to previously-focused element on destroy', () => {
		const outside = document.createElement('button');
		outside.textContent = 'outside';
		document.body.appendChild(outside);
		outside.focus();
		expect(document.activeElement).toBe(outside);

		const { container } = makeContainer();
		const action = focusTrap(container);
		expect(document.activeElement).toBe(container);

		action.destroy();
		expect(document.activeElement).toBe(outside);
	});

	it('calls onEscape when Escape is pressed', async () => {
		const onEscape = vi.fn();
		const { container } = makeContainer();
		const action = focusTrap(container, { onEscape });

		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onEscape).toHaveBeenCalledTimes(1);

		action.destroy();
	});

	it('adds the keydown listener to document (not just the node)', async () => {
		const onEscape = vi.fn();
		const { container } = makeContainer();
		const action = focusTrap(container, { onEscape });

		// Dispatch on document itself — listener must be on document
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onEscape).toHaveBeenCalledTimes(1);

		action.destroy();
	});

	it('removes the listener on destroy (no more events after destroy)', async () => {
		const onEscape = vi.fn();
		const { container } = makeContainer();
		const action = focusTrap(container, { onEscape });
		action.destroy();

		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onEscape).not.toHaveBeenCalled();
	});

	it('traps Tab: wraps from last button to first', async () => {
		const { container, buttons } = makeContainer(2);
		const action = focusTrap(container);

		buttons[1].focus();
		expect(document.activeElement).toBe(buttons[1]);

		await fireEvent.keyDown(document, { key: 'Tab', shiftKey: false });
		expect(document.activeElement).toBe(buttons[0]);

		action.destroy();
	});

	it('traps Shift+Tab: wraps from first button to last', async () => {
		const { container, buttons } = makeContainer(2);
		const action = focusTrap(container);

		buttons[0].focus();
		expect(document.activeElement).toBe(buttons[0]);

		await fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
		expect(document.activeElement).toBe(buttons[1]);

		action.destroy();
	});

	it('update() changes onEscape handler', async () => {
		const first = vi.fn();
		const second = vi.fn();
		const { container } = makeContainer();
		const action = focusTrap(container, { onEscape: first });

		action.update({ onEscape: second });
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(first).not.toHaveBeenCalled();
		expect(second).toHaveBeenCalledTimes(1);

		action.destroy();
	});

	it('lets only the topmost trap handle Escape and restores the trap below it', async () => {
		const outerEscape = vi.fn();
		const innerEscape = vi.fn();
		const outer = makeContainer();
		const outerAction = focusTrap(outer.container, { onEscape: outerEscape });
		outer.buttons[0].focus();
		const inner = makeContainer();
		const innerAction = focusTrap(inner.container, { onEscape: innerEscape });

		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(innerEscape).toHaveBeenCalledTimes(1);
		expect(outerEscape).not.toHaveBeenCalled();

		innerAction.destroy();
		expect(document.activeElement).toBe(outer.buttons[0]);
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(outerEscape).toHaveBeenCalledTimes(1);

		outerAction.destroy();
	});

	it('lets only the topmost trap contain focus and handle Tab', async () => {
		const outer = makeContainer();
		const outerAction = focusTrap(outer.container);
		const inner = makeContainer();
		const innerAction = focusTrap(inner.container);
		const outerFirstFocus = vi.spyOn(outer.buttons[0], 'focus');

		outer.buttons[1].focus();
		expect(document.activeElement).toBe(inner.container);

		inner.buttons[1].focus();
		await fireEvent.keyDown(document, { key: 'Tab' });
		expect(document.activeElement).toBe(inner.buttons[0]);
		expect(outerFirstFocus).not.toHaveBeenCalled();

		innerAction.destroy();
		outerAction.destroy();
	});

	it('removes traps destroyed out of order without stealing focus or leaving stale ownership', async () => {
		const outerEscape = vi.fn();
		const innerEscape = vi.fn();
		const outer = makeContainer();
		const outerAction = focusTrap(outer.container, { onEscape: outerEscape });
		const inner = makeContainer();
		const innerAction = focusTrap(inner.container, { onEscape: innerEscape });

		outerAction.destroy();
		expect(document.activeElement).toBe(inner.container);
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(innerEscape).toHaveBeenCalledTimes(1);
		expect(outerEscape).not.toHaveBeenCalled();

		innerAction.destroy();
		const freshEscape = vi.fn();
		const fresh = makeContainer();
		const freshAction = focusTrap(fresh.container, { onEscape: freshEscape });
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(freshEscape).toHaveBeenCalledTimes(1);
		expect(innerEscape).toHaveBeenCalledTimes(1);
		freshAction.destroy();
	});
});
