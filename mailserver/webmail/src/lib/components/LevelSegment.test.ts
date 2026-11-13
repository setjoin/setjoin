import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import LevelSegment from './LevelSegment.svelte';

describe('LevelSegment', () => {
	it('renders a radiogroup with the three levels, current value checked', () => {
		render(LevelSegment, { value: 'freebusy', label: 'Visibility level', onChange: () => {} });
		const group = screen.getByRole('radiogroup', { name: 'Visibility level' });
		expect(group).toBeTruthy();
		const radios = screen.getAllByRole('radio');
		expect(radios.length).toBe(3);
		expect(radios[1].getAttribute('aria-checked')).toBe('true');
		// roving tabindex: only the checked option is tabbable
		expect(radios[1].getAttribute('tabindex')).toBe('0');
		expect(radios[0].getAttribute('tabindex')).toBe('-1');
	});

	it('clicking an option selects it', async () => {
		const onChange = vi.fn();
		render(LevelSegment, { value: 'none', label: 'Visibility level', onChange });
		const radios = screen.getAllByRole('radio');
		await fireEvent.click(radios[2]);
		expect(onChange).toHaveBeenCalledWith('read');
	});

	it('ArrowRight selects the next level; ArrowLeft wraps back', async () => {
		const onChange = vi.fn();
		render(LevelSegment, { value: 'none', label: 'Visibility level', onChange });
		const radios = screen.getAllByRole('radio');
		await fireEvent.keyDown(radios[0], { key: 'ArrowRight' });
		expect(onChange).toHaveBeenCalledWith('freebusy');
		await fireEvent.keyDown(radios[0], { key: 'ArrowLeft' });
		expect(onChange).toHaveBeenCalledWith('read'); // wraps to the end
	});

	it('disabled blocks selection', async () => {
		const onChange = vi.fn();
		render(LevelSegment, { value: 'none', label: 'Visibility level', onChange, disabled: true });
		const radios = screen.getAllByRole('radio');
		await fireEvent.click(radios[1]);
		expect(onChange).not.toHaveBeenCalled();
	});
});
