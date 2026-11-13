// mailserver/webmail/src/lib/components/ui/SplitPane.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { createRawSnippet, tick } from 'svelte';
import SplitPane from './SplitPane.svelte';

const paneA = createRawSnippet(() => ({ render: () => '<div data-testid="pane-a">A</div>' }));
const paneB = createRawSnippet(() => ({ render: () => '<div data-testid="pane-b">B</div>' }));

function defaults() {
	return { storageKey: 'test.split', minA: 200, minB: 200, a: paneA, b: paneB };
}

// jsdom has no layout: pin clientWidth, then trigger the window-resize fallback path.
async function sizeContainer(container: HTMLElement, px: number) {
	const el = container.querySelector('.split') as HTMLElement;
	Object.defineProperty(el, 'clientWidth', { value: px, configurable: true });
	await fireEvent(window, new Event('resize'));
	await tick();
}

function paneWrapperA(): HTMLElement {
	return screen.getByTestId('pane-a').parentElement as HTMLElement;
}
function paneWrapperB(): HTMLElement {
	return screen.getByTestId('pane-b').parentElement as HTMLElement;
}

describe('SplitPane', () => {
	beforeEach(() => {
		localStorage.clear();
	});

	it('splits the measured width by the default ratio with clamp limits exposed', async () => {
		const { container } = render(SplitPane, defaults());
		await sizeContainer(container, 1000);
		// usable = 999, round(0.5 * 999) = 500
		expect(paneWrapperA().style.width).toBe('500px');
		const sep = screen.getByRole('separator');
		expect(sep).toHaveAttribute('aria-valuenow', '500');
		expect(sep).toHaveAttribute('aria-valuemin', '200');
		expect(sep).toHaveAttribute('aria-valuemax', '799');
	});

	it('restores a persisted ratio', async () => {
		localStorage.setItem('test.split', '0.3');
		const { container } = render(SplitPane, defaults());
		await sizeContainer(container, 1000);
		expect(paneWrapperA().style.width).toBe('300px'); // round(0.3 * 999)
	});

	it('falls back to defaultRatio for an invalid persisted value', async () => {
		localStorage.setItem('test.split', 'garbage');
		const { container } = render(SplitPane, defaults());
		await sizeContainer(container, 1000);
		expect(paneWrapperA().style.width).toBe('500px');
	});

	it('grows pane A by 16px on ArrowRight and persists the new ratio', async () => {
		const { container } = render(SplitPane, defaults());
		await sizeContainer(container, 1000);
		await fireEvent.keyDown(screen.getByRole('separator'), { key: 'ArrowRight' });
		expect(paneWrapperA().style.width).toBe('516px');
		expect(parseFloat(localStorage.getItem('test.split') as string)).toBeCloseTo(516 / 999, 5);
	});

	it('resets to defaultRatio on double-click and persists', async () => {
		localStorage.setItem('test.split', '0.3');
		const { container } = render(SplitPane, defaults());
		await sizeContainer(container, 1000);
		expect(paneWrapperA().style.width).toBe('300px');
		await fireEvent.dblClick(screen.getByRole('separator'));
		expect(paneWrapperA().style.width).toBe('500px');
		expect(parseFloat(localStorage.getItem('test.split') as string)).toBeCloseTo(0.5, 5);
	});

	it('follows pointer drags with clamping and persists on release', async () => {
		const { container } = render(SplitPane, defaults());
		await sizeContainer(container, 1000); // pane A = 500
		const sep = screen.getByRole('separator');
		await fireEvent.pointerDown(sep, { clientX: 600, pointerId: 1 });
		await fireEvent.pointerMove(sep, { clientX: 650, pointerId: 1 });
		expect(paneWrapperA().style.width).toBe('550px'); // 500 + 50
		await fireEvent.pointerMove(sep, { clientX: 0, pointerId: 1 });
		expect(paneWrapperA().style.width).toBe('200px'); // 500 - 600 → clamped to minA
		await fireEvent.pointerUp(sep, { pointerId: 1 });
		expect(parseFloat(localStorage.getItem('test.split') as string)).toBeCloseTo(200 / 999, 5);
	});

	it('collapses pane B (kept mounted) when minimums cannot fit, and restores', async () => {
		const onCollapse = vi.fn();
		const { container } = render(SplitPane, { ...defaults(), minA: 360, minB: 320, onCollapse });
		// width 0 = unmeasured: must not collapse-notify
		expect(onCollapse).not.toHaveBeenCalled();
		await sizeContainer(container, 500); // usable 499 < 680
		expect(onCollapse).toHaveBeenCalledTimes(1);
		expect(paneWrapperB().hidden).toBe(true); // keep-alive: mounted but hidden
		expect(screen.getByTestId('pane-b')).toBeInTheDocument();
		expect(screen.queryByRole('separator')).toBeNull();
		await sizeContainer(container, 1200); // auto-restore
		expect(paneWrapperB().hidden).toBe(false);
		expect(screen.getByRole('separator')).toBeInTheDocument();
		expect(paneWrapperA().style.width).toBe('600px'); // round(0.5 * 1199)
		expect(onCollapse).toHaveBeenCalledTimes(1); // no re-fire on restore
	});
});
