// mailserver/webmail/src/lib/components/ui/Resizer.test.ts
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import Resizer from './Resizer.svelte';

describe('Resizer', () => {
	it('renders a focusable vertical separator with value semantics', () => {
		render(Resizer, { label: 'Resize sidebar', valueNow: 232, valueMin: 200, valueMax: 320 });
		const sep = screen.getByRole('separator');
		expect(sep).toHaveAttribute('aria-orientation', 'vertical');
		expect(sep).toHaveAttribute('aria-label', 'Resize sidebar');
		expect(sep).toHaveAttribute('tabindex', '0');
		expect(sep).toHaveAttribute('aria-valuenow', '232');
		expect(sep).toHaveAttribute('aria-valuemin', '200');
		expect(sep).toHaveAttribute('aria-valuemax', '320');
	});

	it('steps -16/+16 on ArrowLeft/ArrowRight', async () => {
		const onStep = vi.fn();
		render(Resizer, { label: 'Resize', onStep });
		const sep = screen.getByRole('separator');
		await fireEvent.keyDown(sep, { key: 'ArrowRight' });
		expect(onStep).toHaveBeenCalledWith(16);
		await fireEvent.keyDown(sep, { key: 'ArrowLeft' });
		expect(onStep).toHaveBeenCalledWith(-16);
		expect(onStep).toHaveBeenCalledTimes(2);
	});

	it('ignores other keys', async () => {
		const onStep = vi.fn();
		render(Resizer, { label: 'Resize', onStep });
		await fireEvent.keyDown(screen.getByRole('separator'), { key: 'ArrowUp' });
		expect(onStep).not.toHaveBeenCalled();
	});

	it('calls onReset on double-click', async () => {
		const onReset = vi.fn();
		render(Resizer, { label: 'Resize', onReset });
		await fireEvent.dblClick(screen.getByRole('separator'));
		expect(onReset).toHaveBeenCalledTimes(1);
	});

	it('reports drag travel relative to the pointer-down position', async () => {
		const onDragStart = vi.fn();
		const onDrag = vi.fn();
		const onDragEnd = vi.fn();
		render(Resizer, { label: 'Resize', onDragStart, onDrag, onDragEnd });
		const sep = screen.getByRole('separator');
		await fireEvent.pointerDown(sep, { clientX: 500, pointerId: 1 });
		expect(onDragStart).toHaveBeenCalledTimes(1);
		await fireEvent.pointerMove(sep, { clientX: 540, pointerId: 1 });
		expect(onDrag).toHaveBeenCalledWith(40);
		await fireEvent.pointerMove(sep, { clientX: 460, pointerId: 1 });
		expect(onDrag).toHaveBeenCalledWith(-40);
		await fireEvent.pointerUp(sep, { pointerId: 1 });
		expect(onDragEnd).toHaveBeenCalledTimes(1);
	});

	it('does not report moves before pointerdown', async () => {
		const onDrag = vi.fn();
		render(Resizer, { label: 'Resize', onDrag });
		await fireEvent.pointerMove(screen.getByRole('separator'), { clientX: 540 });
		expect(onDrag).not.toHaveBeenCalled();
	});

	it('stops reporting after pointerup', async () => {
		const onDrag = vi.fn();
		render(Resizer, { label: 'Resize', onDrag });
		const sep = screen.getByRole('separator');
		await fireEvent.pointerDown(sep, { clientX: 500, pointerId: 1 });
		await fireEvent.pointerUp(sep, { pointerId: 1 });
		await fireEvent.pointerMove(sep, { clientX: 999, pointerId: 1 });
		expect(onDrag).not.toHaveBeenCalled();
	});
});
