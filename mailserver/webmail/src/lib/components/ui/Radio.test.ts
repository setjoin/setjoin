import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import Radio from './Radio.svelte';

describe('Radio', () => {
	it('renders the label and associates it with the input', () => {
		render(Radio, { label: 'Every 15 minutes', name: 'interval', value: '15m' });
		const input = screen.getByLabelText('Every 15 minutes') as HTMLInputElement;
		expect(input.type).toBe('radio');
		expect(input.name).toBe('interval');
		expect(input.value).toBe('15m');
	});

	it('reflects the checked prop', () => {
		render(Radio, { label: 'Hourly', name: 'interval', value: '1h', checked: true });
		const input = screen.getByLabelText('Hourly') as HTMLInputElement;
		expect(input.checked).toBe(true);
	});

	it('calls onchange with its value when selected', async () => {
		const onchange = vi.fn();
		render(Radio, { label: 'Daily', name: 'interval', value: '24h', onchange });
		await fireEvent.click(screen.getByLabelText('Daily'));
		expect(onchange).toHaveBeenCalledTimes(1);
		expect(onchange).toHaveBeenCalledWith('24h');
	});

	it('does not call onchange when disabled', async () => {
		const onchange = vi.fn();
		render(Radio, { label: 'Weekly', name: 'interval', value: '7d', disabled: true, onchange });
		const input = screen.getByLabelText('Weekly') as HTMLInputElement;
		expect(input.disabled).toBe(true);
		await fireEvent.click(input);
		expect(onchange).not.toHaveBeenCalled();
	});

	it('draws the visual circle and marks it on when checked', () => {
		const { container } = render(Radio, { label: 'Hourly', name: 'interval', value: '1h', checked: true });
		expect(container.querySelector('.radio__circle')).not.toBeNull();
		expect(container.querySelector('.radio__circle--on')).not.toBeNull();
	});
});
